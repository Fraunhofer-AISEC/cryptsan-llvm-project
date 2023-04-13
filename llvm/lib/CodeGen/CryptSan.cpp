//===-- CryptSan.cpp ---------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of CryptSan.
//
// CryptSan Instrumentation Pass.
//===----------------------------------------------------------------------===//
#define PAC_GLOBALS
#define STACK_PROTECT
#define PAC_PERSONALITY
#define LINUX_TARGET
#define OPTIMIZE_FDCE
#define OPTIMIZE_FTCE
#define DEBUG_TYPE "cryptsan"
// #define PAC_QEMU

// To debug in LTO, we simply always write to dbgs().
#undef LLVM_DBG
/*
#define LLVM_DBG(x)                                                            \
  do {                                                                         \
    x;                                                                         \
  } while (0)
*/
#define LLVM_DBG(x)                                                            \
  do {                                                                         \
    ;                                                                          \
  } while (0)

#include "llvm/CodeGen/CryptSan.h"
#include "llvm-c/Core.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/Hashing.h"
#include "llvm/ADT/MapVector.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/ADT/Triple.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/MemoryLocation.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/TargetLowering.h"
#include "llvm/CodeGen/TargetPassConfig.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/AbstractCallSite.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Comdat.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/ConstantRange.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/DerivedUser.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/IRBuilderFolder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/ModuleSummaryIndex.h"
#include "llvm/IR/ModuleSummaryIndexYAML.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/Value.h"
#include "llvm/InitializePasses.h"
#include "llvm/MC/MCSectionMachO.h"
#include "llvm/Pass.h"
#include "llvm/PassRegistry.h"
#include "llvm/Support/Allocator.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/ScopedPrinter.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include <queue>

using namespace llvm;

const char kCryptSanPersonalityThunkName[] = "__cryptsan_personality_thunk";
static const char *const kCryptSanPrefix = "__cryptsan";
static const char *const kCryptSanCtorPrefix = "cryptsan.";
static const char *const kCryptSanLegacyPassCtorName = "__cryptsan.module_ctor";
static const uint64_t kCryptSanCtorPriority = 0;
static const char *const kCryptSanFnPrefix = "__cryptsan_";
static const char *const kCryptSanInitRtName = "__cryptsan_init_rt";

static bool isUninstrumentedFunction(const Function &F) {
  if (F.isIntrinsic())
    return true;
  return F.isDeclaration();
}

namespace {

class AllocaOffsetRewriter : public SCEVRewriteVisitor<AllocaOffsetRewriter> {
  const Value *AllocaPtr;

public:
  AllocaOffsetRewriter(ScalarEvolution &SE, const Value *AllocaPtr)
      : SCEVRewriteVisitor(SE), AllocaPtr(AllocaPtr) {}

  const SCEV *visitUnknown(const SCEVUnknown *Expr) {
    if (Expr->getValue() == AllocaPtr)
      return SE.getZero(Expr->getType());
    return Expr;
  }
};

} // end anonymous namespace

char CryptSanLegacyPass::ID = 0;

StringRef CryptSanLegacyPass::getPassName() const {
  return "CryptSanLegacyPass";
}

bool CryptSanLegacyPass::doInitialization(Module &M) {
  dbgs() << "Initialize CryptSanLegacyPass for module " << M.getName() << "\n";

  DL = &M.getDataLayout();

  C = &(M.getContext());

  IRBuilder<> Builder(*C);

  Int1Ty = Builder.getInt1Ty();
  Int8Ty = Builder.getInt8Ty();
  Int32Ty = Builder.getInt32Ty();
  Int64Ty = Builder.getInt64Ty();
  IntptrTy = Builder.getIntPtrTy(*DL);
  PtrTy = Builder.getInt8PtrTy();
  DoublePtrTy = PointerType::getUnqual(PtrTy);
  TriplePtrTy = PointerType::getUnqual(DoublePtrTy);
  Ptr32Ty = PointerType::getUnqual(Int32Ty);
  Ptr64Ty = PointerType::getUnqual(Int64Ty);
  VoidTy = Builder.getVoidTy();

  return true;
}

void CryptSanLegacyPass::createCtorAndInitFunctions(Module &M) {
  // Create the main constructor and add a call to our runtime initialization.
  std::tie(MainCtorFn, std::ignore) = createSanitizerCtorAndInitFunctions(
      M, kCryptSanLegacyPassCtorName, kCryptSanInitRtName, /*InitArgTypes=*/{},
      /*InitArgs=*/{});

  appendToGlobalCtors(M, MainCtorFn, kCryptSanCtorPriority);
}

void CryptSanLegacyPass::initializeCallbacks(Module &M) {

  auto malloc_names = {"malloc", "_Znam", "_Znwm", "_ZnamRKSt9nothrow_t",
                       "_ZnwmRKSt9nothrow_t"};
  auto free_names = {"free", "_ZdaPv", "_ZdlPv", "_ZdaPvRKSt9nothrow_t",
                     "_ZdlPvRKSt9nothrow_t"};

  CryptSanAutFn = M.getOrInsertFunction(
      "__cryptsan_aut_pointer", FunctionType::get(PtrTy, {PtrTy}, false));

  CryptSanInitGlobalFn = M.getOrInsertFunction(
      "__cryptsan_init_global",
      FunctionType::get(VoidTy, {PtrTy, DoublePtrTy, Int32Ty}, false));

  CryptSanInitGlobalWithNameFn = M.getOrInsertFunction(
      "__cryptsan_init_global_with_id",
      FunctionType::get(VoidTy, {Int32Ty, PtrTy, DoublePtrTy, Int32Ty}, false));

  CryptSanInitMainArgsFn = M.getOrInsertFunction(
      "__cryptsan_init_main_args",
      FunctionType::get(VoidTy, {Ptr32Ty, TriplePtrTy}, false));

  CryptSanDebugFn = M.getOrInsertFunction(
      "__cryptsan_debug",
      FunctionType::get(VoidTy, {Int32Ty, PtrTy, DoublePtrTy}, false));

  CryptSanMallocFn = M.getOrInsertFunction(
      "__cryptsan_malloc", FunctionType::get(PtrTy, {Int64Ty}, false));

  CryptSanFreeFn = M.getOrInsertFunction(
      "__cryptsan_free", FunctionType::get(VoidTy, {PtrTy}, false));

  CryptSanFreeStackVariableFn =
      M.getOrInsertFunction("__cryptsan_free_stack_variable",
                            FunctionType::get(VoidTy, {PtrTy, Int32Ty}, false));

  for (auto name : malloc_names) {
    M.getOrInsertFunction(name, FunctionType::get(PtrTy, {Int64Ty}, false))
        .getCallee()
        ->replaceAllUsesWith(CryptSanMallocFn.getCallee());
  }
  for (auto name : free_names) {
    M.getOrInsertFunction(name, FunctionType::get(VoidTy, {PtrTy}, false))
        .getCallee()
        ->replaceAllUsesWith(CryptSanFreeFn.getCallee());
  }

  CryptSanApplyMaskFn = M.getOrInsertFunction(
      "__cryptsan_reapply_mask", FunctionType::get(PtrTy, {PtrTy}, false));

  CryptSanCallocFn = M.getOrInsertFunction(
      "__cryptsan_calloc", FunctionType::get(PtrTy, {Int64Ty, Int64Ty}, false));

  FunctionCallee DefaultCallocFn = M.getOrInsertFunction(
      "calloc", FunctionType::get(PtrTy, {Int64Ty, Int64Ty}, false));
  DefaultCallocFn.getCallee()->replaceAllUsesWith(CryptSanCallocFn.getCallee());

  CryptSanReallocFn = M.getOrInsertFunction(
      "__cryptsan_realloc", FunctionType::get(PtrTy, {PtrTy, Int64Ty}, false));

  FunctionCallee DefaultReallocFn = M.getOrInsertFunction(
      "realloc", FunctionType::get(PtrTy, {PtrTy, Int64Ty}, false));

  DefaultReallocFn.getCallee()->replaceAllUsesWith(
      CryptSanReallocFn.getCallee());

  CryptSanMemmoveFn = M.getOrInsertFunction("__cryptsan_memmove", PtrTy, PtrTy,
                                            PtrTy, IntptrTy);
  CryptSanMemcpyFn =
      M.getOrInsertFunction("__cryptsan_memcpy", PtrTy, PtrTy, PtrTy, IntptrTy);
  CryptSanMemsetFn = M.getOrInsertFunction("__cryptsan_memset", PtrTy, PtrTy,
                                           Int32Ty, IntptrTy);
}

void CryptSanLegacyPass::redirectLibFunction(Function *F) {

  if (!F)
    return;

  StringRef Name = GlobalValue::dropLLVMManglingEscape(F->getName());
  // Ignore functions inserted by the compiler (this includes intrinsics).
  if (Name.startswith("llvm."))
    return;
  // Ignore functions inserted by this pass.
  if (Name.startswith(kCryptSanFnPrefix))
    return;
  // Ignore functions that are instrumented anyways.
  if (!isUninstrumentedFunction(*F))
    return;

  bool changed = true;

  if (Name == "reallocarray") {
    F->setName(Twine(kCryptSanFnPrefix) + "reallocarray");
  } else if (Name == "mmap") {
    F->setName(Twine(kCryptSanFnPrefix) + "mmap");
  } else if (Name == "memmove") {
    F->setName(Twine(kCryptSanFnPrefix) + "memmove");
  } else if (Name == "__memmove_chk") {
    F->setName(Twine(kCryptSanFnPrefix) + "__memmove_chk");
  } else if (Name == "memcpy") {
    F->setName(Twine(kCryptSanFnPrefix) + "memcpy");
  } else if (Name == "__memcpy_chk") {
    F->setName(Twine(kCryptSanFnPrefix) + "__memcpy_chk");
  } else if (Name == "wcscpy") {
    F->setName(Twine(kCryptSanFnPrefix) + "wcscpy");
  } else if (Name == "strcpy") {
    F->setName(Twine(kCryptSanFnPrefix) + "strcpy");
  } else if (Name == "__strcpy_chk") {
    F->setName(Twine(kCryptSanFnPrefix) + "__strcpy_chk");
  } else if (Name == "__strncpy_chk") {
    F->setName(Twine(kCryptSanFnPrefix) + "__strncpy_chk");
  } else if (Name == "strncpy") {
    F->setName(Twine(kCryptSanFnPrefix) + "strncpy");
  } else if (Name == "strncat") {
    F->setName(Twine(kCryptSanFnPrefix) + "strncat");
  } else if (Name == "strtok") {
    F->setName(Twine(kCryptSanFnPrefix) + "strtok");
  } else if (Name == "__strncat_chk") {
    F->setName(Twine(kCryptSanFnPrefix) + "__strncat_chk");
  } else if (Name == "strcat") {
    F->setName(Twine(kCryptSanFnPrefix) + "strcat");
  } else if (Name == "__strcat_chk") {
    F->setName(Twine(kCryptSanFnPrefix) + "__strcat_chk");
  } else {
    changed = false;
  }
  if (changed) {
    LLVM_DBG(dbgs() << "redirectLibFunction to " << F->getName() << "\n");
  }
}

bool CryptSanLegacyPass::canSkipPointer(
    const Value *PointerOperand, std::vector<const Value *> AlreadyProcessed) {
  auto it = SkippablePointers.find(PointerOperand);
  if (it != SkippablePointers.end()) {
    return true;
  }
  it = NotSkippablePointers.find(PointerOperand);
  if (it != NotSkippablePointers.end()) {
    return false;
  }

  auto it2 = std::find(AlreadyProcessed.begin(), AlreadyProcessed.end(),
                       PointerOperand);
  if (it2 != AlreadyProcessed.end()) {
    NotSkippablePointers.insert(PointerOperand);
    return false;
  }
  AlreadyProcessed.push_back(PointerOperand);

  if (isa<AllocaInst>(PointerOperand)) {
    SkippablePointers.insert(PointerOperand);
    return true;
  } else if (isa<Constant>(PointerOperand)) {
    SkippablePointers.insert(PointerOperand);
    return true;
  } else if (isa<GlobalVariable>(PointerOperand)) {
    SkippablePointers.insert(PointerOperand);
    return true;
  } else if (const BitCastInst *BCI = dyn_cast<BitCastInst>(PointerOperand)) {
    return canSkipPointer(BCI->getOperand(0), AlreadyProcessed);

  } else if (isa<MetadataAsValue>(PointerOperand)) {
    SkippablePointers.insert(PointerOperand);
    return true;
  } else if (const GEPOperator *GEP = dyn_cast<GEPOperator>(PointerOperand)) {
    return canSkipPointer(GEP->getPointerOperand(), AlreadyProcessed);
  } else if (const PHINode *phi = dyn_cast<PHINode>(PointerOperand)) {
    unsigned N = phi->getNumIncomingValues();
    for (unsigned i = 0; i < N; i++) {
      if (!canSkipPointer(phi->getIncomingValue(i), AlreadyProcessed)) {
        NotSkippablePointers.insert(PointerOperand);
        return false;
      }
    }
    SkippablePointers.insert(PointerOperand);
    return true;
  } else if (const SelectInst *sel = dyn_cast<SelectInst>(PointerOperand)) {
    return canSkipPointer(sel->getTrueValue(), AlreadyProcessed) &&
           canSkipPointer(sel->getFalseValue(), AlreadyProcessed);
  }

  NotSkippablePointers.insert(PointerOperand);
  return false;
}

bool CryptSanLegacyPass::checkLoadStoreSourceIsGEP(Instruction *load_store,
                                                   Value *gep_source) {

  Value *pointer_operand = NULL;

  if (!isa<LoadInst>(load_store) && !isa<StoreInst>(load_store))
    return false;

  if (isa<LoadInst>(load_store)) {
    pointer_operand = load_store->getOperand(0);
  }

  if (isa<StoreInst>(load_store)) {
    pointer_operand = load_store->getOperand(1);
  }

  assert(pointer_operand && "pointer_operand null?");

  if (!isa<GetElementPtrInst>(pointer_operand))
    return false;

  GetElementPtrInst *gep_ptr = dyn_cast<GetElementPtrInst>(pointer_operand);
  assert(gep_ptr && "gep_ptr null?");

  Value *gep_ptr_operand = gep_ptr->getOperand(0);

  if (gep_ptr_operand == gep_source)
    return true;

  return false;
}

bool CryptSanLegacyPass::getRecursivePointerArgs(Value *V,
                                                 std::set<Value *> &set) {
  set.insert(V);
  if (auto pi = dyn_cast<Instruction>(V)) {
    for (Use &operand : pi->operands()) {
      if (set.count(operand)) {
        continue;
      }
      if (isDereferencableType(operand->getType())) {
        getRecursivePointerArgs(operand, set);
      }
    }
  }
  return true;
}

bool CryptSanLegacyPass::callHasDependentPointerArgs(CallBase *CB,
                                                     Instruction *load_store) {
  static int total = 0;
  static int dependent = 0;
  static std::map<CallBase *, std::set<Value *>> CallDependentMap;
  total++;

  std::set<Value *> loadStoreDependent;

  if (!CallDependentMap.count(CB)) {
    auto callDependent = new std::set<Value *>();
    for (auto &U : CB->args()) {
      if (isDereferencableType(U->getType())) {
        getRecursivePointerArgs(U, *callDependent);
      }
    }
    CallDependentMap[CB] = *callDependent;
  }
  for (Use &U : load_store->operands()) {
    getRecursivePointerArgs(U, loadStoreDependent);
  }
  for (auto &U : CallDependentMap[CB]) {
    if (loadStoreDependent.count(U)) {
      dependent++;
      return true;
    }
  }
  return false;
}

bool CryptSanLegacyPass::callInstBetween(Instruction *load_store,
                                         Instruction *end) {
  BasicBlock *bb_start = load_store->getParent();
  BasicBlock *bb_end = end->getParent();

  for (Instruction *I = load_store; I != nullptr; I = I->getNextNode()) {
    if (CallBase *CB = dyn_cast<CallBase>(I)) {
      if (callHasDependentPointerArgs(CB, load_store)) {
        return true;
      }
    }
  }

  for (Instruction &I : *bb_end) {
    if (&I == end)
      break;
    if (CallBase *CB = dyn_cast<CallBase>(&I)) {
      if (callHasDependentPointerArgs(CB, load_store)) {
        return true;
      }
    }
  }

  std::set<BasicBlock *> bb_visited;
  SmallVector<BasicBlock *, 8> bb_worklist;

  bb_worklist.push_back(bb_end);
  bb_visited.insert(bb_end);
  bb_visited.insert(bb_start);
  while (!bb_worklist.empty()) {
    BasicBlock *bb_curr = bb_worklist.pop_back_val();
    for (BasicBlock *bb_pred : children<Inverse<BasicBlock *>>(bb_curr)) {
      if (bb_visited.insert(bb_pred).second) {
        bb_worklist.push_back(bb_pred);
      }
    }
  }

  bb_visited.erase(bb_end);
  bb_visited.erase(bb_start);

  for (BasicBlock *BB : bb_visited) {
    for (Instruction &I : *BB) {
      if (CallBase *CB = dyn_cast<CallBase>(&I)) {
        if (callHasDependentPointerArgs(CB, load_store)) {
          return true;
        }
      }
    }
  }
  return false;
}

void CryptSanLegacyPass::bbDerefCheck(Function &F,
                                      std::map<Value *, Value *> &FDCE_map) {

  if (F.isDeclaration())
    return;

  int func_nr_of_load_stores = 0;
  int func_nr_of_redundant_checks = 0;

  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      Value *pointer_operand = NULL;

      if (isa<LoadInst>(&I)) {
        LoadInst *ldi = dyn_cast<LoadInst>(&I);
        assert(ldi && "not a load instruction");
        pointer_operand = ldi->getPointerOperand();
      } else if (isa<StoreInst>(&I)) {
        StoreInst *sti = dyn_cast<StoreInst>(&I);
        assert(sti && "not a store instruction");
        pointer_operand = sti->getPointerOperand();
      } else {
        continue;
      }

      func_nr_of_load_stores++;

      assert(pointer_operand && "pointer operand null?");

      if (FDCE_map.count(&I)) {
        func_nr_of_redundant_checks++;
        continue;
      }

      for (User *U : pointer_operand->users()) {
        Instruction *temp_inst = dyn_cast<Instruction>(U);
        if (!temp_inst)
          continue;

        if (temp_inst == &I)
          continue;

        if (!isa<LoadInst>(temp_inst) && !isa<StoreInst>(temp_inst))
          continue;

        if (StoreInst *SI = dyn_cast<StoreInst>(temp_inst)) {
          if (SI->getPointerOperand() != pointer_operand) {
            continue;
          }
        }

        if (m_dominator_tree->dominates(&I, temp_inst)) {
          if (!callInstBetween(&I, temp_inst)) {
            if (!FDCE_map.count(temp_inst)) {
              FDCE_map[temp_inst] = &I;
              continue;
            }
          }
        }
      }
    }
  }

  nr_of_redundant_checks += func_nr_of_redundant_checks;
  nr_of_load_stores += func_nr_of_load_stores;

  return;
}

void CryptSanLegacyPass::bbSameLockCheck(Function &F,
                                         std::map<Value *, Value *> &FTCE_map) {

  if (F.isDeclaration())
    return;

  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      Value *pointer_operand = NULL;

      if (isa<LoadInst>(&I)) {
        LoadInst *ldi = dyn_cast<LoadInst>(&I);
        assert(ldi && "not a load instruction");
        pointer_operand = ldi->getPointerOperand();
      } else if (isa<StoreInst>(&I)) {
        StoreInst *sti = dyn_cast<StoreInst>(&I);
        assert(sti && "not a store instruction");
        pointer_operand = sti->getPointerOperand();
      } else {
        continue;
      }
      Instruction *load_store = &I;

      if (FTCE_map.count(load_store))
        return;

      Value *gep_source = NULL;
      if (isa<GetElementPtrInst>(pointer_operand)) {

        GetElementPtrInst *ptr_gep =
            dyn_cast<GetElementPtrInst>(pointer_operand);
        assert(ptr_gep && "[bbTemporalCheckElimination] gep_inst null?");
        gep_source = ptr_gep->getOperand(0);
      } else {
        gep_source = pointer_operand;
      }

      BasicBlock *bb_curr = load_store->getParent();
      assert(bb_curr && "bb null?");

      std::set<BasicBlock *> bb_visited;
      std::queue<BasicBlock *> bb_worklist;

      bb_worklist.push(bb_curr);
      BasicBlock *bb = NULL;
      while (bb_worklist.size() != 0) {

        bb = bb_worklist.front();
        assert(bb && "Not a BasicBlock?");

        bb_worklist.pop();
        if (bb_visited.count(bb)) {
          continue;
        }
        bb_visited.insert(bb);

        bool break_flag = false;

        if (bb == bb_curr) {
          Instruction *next_inst = getNextInstruction(load_store);
          BasicBlock *next_inst_bb = next_inst->getParent();
          while ((next_inst_bb == bb_curr) &&
                 (next_inst != bb_curr->getTerminator())) {

            if (isa<CallInst>(next_inst)) {
              break_flag = true;
              break;
            }

            if (checkLoadStoreSourceIsGEP(next_inst, gep_source)) {
              if (m_dominator_tree->dominates(load_store, next_inst)) {
                FTCE_map[next_inst] = load_store;
                nr_of_shared_lock_checks++;
              }
            }

            next_inst = getNextInstruction(next_inst);
            next_inst_bb = next_inst->getParent();
          }
        } else {
          for (BasicBlock::iterator i = bb->begin(), ie = bb->end(); i != ie;
               ++i) {
            Instruction *new_inst = dyn_cast<Instruction>(i);
            if (isa<CallInst>(new_inst)) {
              break_flag = true;
              break;
            }

            if (checkLoadStoreSourceIsGEP(new_inst, gep_source)) {

              if (m_dominator_tree->dominates(load_store, new_inst)) {
                FTCE_map[new_inst] = load_store;
                nr_of_shared_lock_checks++;
              }
            }
          }
        }

        for (succ_iterator si = succ_begin(bb), se = succ_end(bb); si != se;
             ++si) {

          if (break_flag)
            break;

          BasicBlock *next_bb = cast<BasicBlock>(*si);
          bb_worklist.push(next_bb);
        }
      }
    }
  }
}

bool CryptSanLegacyPass::postDominates(Instruction *A, Instruction *B) {
  const BasicBlock *ABB = A->getParent();
  const BasicBlock *BBB = B->getParent();

  if (ABB != BBB)
    return m_post_dominator_tree->dominates(ABB, BBB);

  for (const Instruction &I : *ABB) {
    if (&I == B)
      return true;
    if (&I == A)
      return false;
  }
  llvm_unreachable("Corrupt instruction list");
}

void CryptSanLegacyPass::findRedundantChecks(Instruction *checked_load_store,
                                             std::map<Value *, int> &FDCE_map,
                                             Value *pointer_operand,
                                             bool goneThroughGEP) {

  for (User *U : pointer_operand->users()) {

    if (GEPOperator *GEP = dyn_cast<GEPOperator>(U)) {
      findRedundantChecks(checked_load_store, FDCE_map, GEP, true);
      continue;
    }

    Instruction *load_store = dyn_cast<Instruction>(U);

    if (!load_store)
      continue;

    if (load_store == checked_load_store)
      continue;

    if (!isa<LoadInst>(load_store) && !isa<StoreInst>(load_store))
      continue;

    if (StoreInst *SI = dyn_cast<StoreInst>(load_store)) {
      if (SI->getPointerOperand() != pointer_operand) {
        // not used as pointer operand but value operand, check not redundant
        continue;
      }
    }

    // If the load/store is after a GEP, we must additionally ensure that it
    // post-dominates the original, checked instr
    if (goneThroughGEP)
      if (!m_dominator_tree->dominates(load_store, checked_load_store))
        continue;

    // Original Str must dominate str
    if (m_dominator_tree->dominates(checked_load_store, load_store)) {
      if (!callInstBetween(checked_load_store, load_store))
        if (!FDCE_map.count(load_store))
          FDCE_map[load_store] = true;
    }
  } // Iterating over uses ends
}

Value *CryptSanLegacyPass::stripPointer(Instruction *I, Value *pointeroperand) {
  IRBuilder<> Builder(I);
  // auto tempI = I;
  // while (!Builder.getCurrentDebugLocation()) {
  //   tempI = tempI->getNextNode();
  //   Builder.SetCurrentDebugLocation(tempI->getDebugLoc());
  // }
  LLVM_DBG(dbgs() << "Strip with po " << *pointeroperand << "used in " << *I
                  << "\n");

  auto poType = pointeroperand->getType();

#ifdef LINUX_TARGET
  llvm::Constant *StripMask =
      llvm::ConstantInt::get(Int64Ty, 0x0000FFFFFFFFFFFFULL, false);
#else
  llvm::Constant *StripMask =
      llvm::ConstantInt::get(Int64Ty, 0x000000FFFFFFFFFFULL, false);
#endif

  auto Address = Builder.CreatePtrToInt(pointeroperand, Int64Ty);
  auto StrippedAddress = Builder.CreateAnd(Address, StripMask);
  Value *ReturnPointer = Builder.CreateIntToPtr(StrippedAddress, poType);

  return ReturnPointer;
}
void CryptSanLegacyPass::applyMask(Instruction *I) {
  if (dyn_cast<InvokeInst>(I)) {
    return;
  }

  bool cont = false;
  std::vector<Instruction *> dependend_insts;
  for (auto *U : I->users()) {
    if (Instruction *Inst = dyn_cast<Instruction>(U)) {
      dependend_insts.push_back(Inst);
      cont = true;
    }
  }
  if (!cont) {
    return;
  }
  nr_of_masks_applied++;
  IRBuilder<> Builder(I->getNextNode());
  auto poType = I->getType();
  Value *CastedReturn = Builder.CreatePointerCast(I, PtrTy);
  Value *args[]{CastedReturn};
  Value *MaskedPointer = Builder.CreateCall(CryptSanApplyMaskFn, args);
  auto new_name = "__remasked" + Twine(I->getName());
  Value *ReturnPointer =
      Builder.CreatePointerCast(MaskedPointer, poType, new_name);
  for (auto *Inst : dependend_insts) {
    Inst->replaceUsesOfWith(I, ReturnPointer);
  }
}

PHINode *CryptSanLegacyPass::autPointer(Instruction *I, Value *pointeroperand) {
  IRBuilder<> Builder(I);
  auto tempI = I;
  while (!Builder.getCurrentDebugLocation()) {
    tempI = tempI->getNextNode();
    Builder.SetCurrentDebugLocation(tempI->getDebugLoc());
  }

  llvm::Constant *GetTagMask =
      llvm::ConstantInt::get(Int64Ty, 0xFFFFF80000000000ULL, false);
  llvm::Constant *StripTagMask =
      llvm::ConstantInt::get(Int64Ty, 0x000007FFFFFFFFFFULL, false);
  llvm::Constant *StripAlignMask =
      llvm::ConstantInt::get(Int64Ty, 0x000007FFFFFFFFFCULL, false);
#ifdef PAC_QEMU
  llvm::Constant *poms_mask =
      llvm::ConstantInt::get(Int64Ty, 0x800000000ULL, false);
#else
  llvm::Constant *poms_mask =
      llvm::ConstantInt::get(Int64Ty, 0x400000000000ULL, false);
#endif
  llvm::Constant *Null32 = llvm::Constant::getNullValue(Int32Ty);

  auto poType = pointeroperand->getType();
  llvm::Value *Address =
      Builder.CreatePtrToInt(pointeroperand, Builder.getInt64Ty());
  Value *UnmarkedAddress = Builder.CreateAnd(Address, StripAlignMask);
  Value *ShadowAddress = Builder.CreateXor(UnmarkedAddress, poms_mask);

  Value *IDPointer = Builder.CreateIntToPtr(ShadowAddress, Ptr32Ty);
  LoadInst *id = Builder.CreateLoad(IDPointer);

  Value *id_64 = Builder.CreateIntCast(id, Int64Ty, false);
  Value *id_available = Builder.CreateICmp(llvm::CmpInst::ICMP_NE, Null32, id);

  Instruction *ThenTerm;
  BasicBlock *OldBlock = (*I).getParent();
  ThenTerm = SplitBlockAndInsertIfThen(id_available, &*I, false);
  BasicBlock *ExitBlock = (*I).getParent();
  BasicBlock *NeedAutBlock = ThenTerm->getParent();
  NeedAutBlock->setName("need_aut");
  Builder.SetInsertPoint(ThenTerm);

  Value *StrippedID = Builder.CreateAnd(StripTagMask, id_64);
  Value *Mask = Builder.CreateAnd(Address, GetTagMask);
  Value *Combined = Builder.CreateOr(Mask, StrippedID);
  Value *CastedPO = Builder.CreateIntToPtr(Combined, poType);
  Value *args[]{CastedPO};

  AutedID_map[I] = id_64;

  auto CryptSanAutdzaFn =
      I->getParent()->getParent()->getParent()->getOrInsertFunction(
          "__cryptsan_par_autdza",
          FunctionType::get(Builder.getInt8PtrTy(), {poType}, false));
  Builder.CreateCall(CryptSanAutdzaFn, args, "unPACed_");
  auto strip = I->getParent()->getParent()->getParent()->getOrInsertFunction(
      "__cryptsan_xpac",
      FunctionType::get(Builder.getInt8PtrTy(), {poType}, false));
  Value *stripargs[] = {pointeroperand};
  auto *StripResult = Builder.CreateCall(strip, stripargs);
  Value *ReturnPointer = Builder.CreatePointerCast(StripResult, poType);

  auto new_name = "__auted" + Twine(I->getName());

  PHINode *PN =
      PHINode::Create(poType, 2, new_name, ExitBlock->getFirstNonPHI());
  PN->addIncoming(pointeroperand, OldBlock);
  PN->addIncoming(ReturnPointer, NeedAutBlock);
  return PN;
}

Value *CryptSanLegacyPass::autByIdPointer(Instruction *I, Value *pointeroperand,
                                          Value *ref_id) {
  IRBuilder<> Builder(I);
  auto tempI = I;
  while (!Builder.getCurrentDebugLocation()) {
    tempI = tempI->getNextNode();
    Builder.SetCurrentDebugLocation(tempI->getDebugLoc());
  }

  llvm::Constant *StripAlignMask =
      llvm::ConstantInt::get(Int64Ty, 0x000007FFFFFFFFFCULL, false);
#ifdef PAC_QEMU
  dbgs() << "## A ##\n";
  llvm::Constant *poms_mask =
      llvm::ConstantInt::get(Int64Ty, 0x800000000ULL, false);
#else
  dbgs() << "## B ##\n";
  llvm::Constant *poms_mask =
      llvm::ConstantInt::get(Int64Ty, 0x400000000000ULL, false);
#endif

  auto poType = pointeroperand->getType();
  Value *args[]{pointeroperand, ref_id};
  auto CryptSanCompIdFn =
      I->getParent()->getParent()->getParent()->getOrInsertFunction(
          "__cryptsan_aut_by_id",
          FunctionType::get(Builder.getInt8PtrTy(), {poType, Int64Ty}, false));
  Value *StripResult = Builder.CreateCall(CryptSanCompIdFn, args, "unPACed_");
  Value *ReturnPointer = Builder.CreatePointerCast(StripResult, poType);

  return ReturnPointer;
}

Value *CryptSanLegacyPass::autPointerAtOffset(Instruction *I,
                                              Value *pointeroperand,
                                              Value *Offset) {
  IRBuilder<> Builder(I);
  auto tempI = I;
  while (!Builder.getCurrentDebugLocation()) {
    tempI = tempI->getNextNode();
    Builder.SetCurrentDebugLocation(tempI->getDebugLoc());
  }
  auto poType = pointeroperand->getType();

  auto CryptSanAutAtOffsetFn =
      I->getParent()->getParent()->getParent()->getOrInsertFunction(
          "__cryptsan_aut_at_offset",
          FunctionType::get(Builder.getInt8PtrTy(), {poType, Int32Ty}, false));
  Value *casted_offset = Builder.CreateIntCast(Offset, Int32Ty, false);
  Value *last_pos = Builder.CreateSub(
      casted_offset, llvm::ConstantInt::get(Int32Ty, 1, false));
  Value *args[] = {pointeroperand, last_pos};
  Value *Stripped = Builder.CreateCall(CryptSanAutAtOffsetFn, args, "unPACed_");
  Value *ReturnPointer = Builder.CreatePointerCast(Stripped, poType);
  return ReturnPointer;
}

void CryptSanLegacyPass::instrumentPersonalityFunctions(Module &M) {
  MapVector<Constant *, std::vector<Function *>> PersonalityFns;
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;

    if (F.hasPersonalityFn()) {
      PersonalityFns[F.getPersonalityFn()->stripPointerCasts()].push_back(&F);
    } else if (!F.hasFnAttribute(Attribute::NoUnwind)) {
      PersonalityFns[nullptr].push_back(&F);
    }
  }

  if (PersonalityFns.empty())
    return;

  FunctionCallee HwasanPersonalityWrapper = M.getOrInsertFunction(
      "__cryptsan_personality_wrapper", Int32Ty, Int32Ty, Int32Ty, Int64Ty,
      PtrTy, PtrTy, PtrTy, PtrTy, PtrTy);
  FunctionCallee UnwindGetGR = M.getOrInsertFunction("_Unwind_GetGR", VoidTy);
  FunctionCallee UnwindGetCFA = M.getOrInsertFunction("_Unwind_GetCFA", VoidTy);

  for (auto &P : PersonalityFns) {
    std::string ThunkName = kCryptSanPersonalityThunkName;
    if (P.first) {
      dbgs() << "Found PersonalityFns: " << P.first->getName().str() << "\n";
      ThunkName += ("." + P.first->getName()).str();
    }
    FunctionType *ThunkFnTy = FunctionType::get(
        Int32Ty, {Int32Ty, Int32Ty, Int64Ty, PtrTy, PtrTy}, false);
    bool IsLocal = P.first && (!isa<GlobalValue>(P.first) ||
                               cast<GlobalValue>(P.first)->hasLocalLinkage());
    auto *ThunkFn = Function::Create(ThunkFnTy,
                                     IsLocal ? GlobalValue::InternalLinkage
                                             : GlobalValue::LinkOnceODRLinkage,
                                     ThunkName, &M);
    if (!IsLocal) {
      ThunkFn->setVisibility(GlobalValue::HiddenVisibility);
      ThunkFn->setComdat(M.getOrInsertComdat(ThunkName));
    }

    auto *BB = BasicBlock::Create(*C, "entry", ThunkFn);
    IRBuilder<> IRB(BB);
    CallInst *WrapperCall = IRB.CreateCall(
        HwasanPersonalityWrapper,
        {ThunkFn->getArg(0), ThunkFn->getArg(1), ThunkFn->getArg(2),
         ThunkFn->getArg(3), ThunkFn->getArg(4),
         P.first ? IRB.CreateBitCast(P.first, PtrTy)
                 : Constant::getNullValue(PtrTy),
         IRB.CreateBitCast(UnwindGetGR.getCallee(), PtrTy),
         IRB.CreateBitCast(UnwindGetCFA.getCallee(), PtrTy)});
    WrapperCall->setTailCall();
    IRB.CreateRet(WrapperCall);

    for (Function *F : P.second)
      F->setPersonalityFn(ThunkFn);
  }
}

Value *CryptSanLegacyPass::forceAutPointer(Instruction *I,
                                           Value *pointeroperand) {
  IRBuilder<> Builder(I);
  // auto tempI = I;
  // while (!Builder.getCurrentDebugLocation()) {
  //   tempI = tempI->getNextNode();
  //   Builder.SetCurrentDebugLocation(tempI->getDebugLoc());
  // }
  auto poType = pointeroperand->getType();

  auto CryptSanForceAutFn =
      I->getParent()->getParent()->getParent()->getOrInsertFunction(
          "__cryptsan_force_aut",
          FunctionType::get(Builder.getInt8PtrTy(), {poType}, false));
  Value *args[] = {pointeroperand};
  Value *Stripped = Builder.CreateCall(CryptSanForceAutFn, args, "unPACed_");
  Value *ReturnPointer = Builder.CreatePointerCast(Stripped, poType);
  return ReturnPointer;
}

void CryptSanLegacyPass::initGlobalsInGlobals(
    Module &M, std::set<std::tuple<Value *, Value *, Value *>> &global_pairs,
    std::set<std::tuple<Value *, int, Value *>> &global_init_replacement) {
  std::vector<Value *> globals;

  for (Module::global_iterator it = M.global_begin(), ite = M.global_end();
       it != ite; ++it) {

    GlobalVariable *gv = dyn_cast<GlobalVariable>(it);

    if (!gv) {
      continue;
    }

    if (gv->getSection() == "llvm.metadata") {
      continue;
    }
    if (gv->getName() == "llvm.global_ctors") {
      continue;
    }

    if (gv->getName().startswith("__pac")) {
      continue;
    }

    if (!gv->hasInitializer()) {
      continue;
    }

    SmallVector<Value *> unsafe_globals;
    SmallVector<Value *> paced_globals;
    for (auto pair : global_pairs) {
      Value *unsafe_gv = std::get<0>(pair);
      unsafe_globals.push_back(unsafe_gv);
      paced_globals.push_back(std::get<1>(pair));
    }
    auto nOperands = gv->getInitializer()->getNumOperands();
    for (unsigned int i = 0; i < nOperands; i++) {
      if (auto gep =
              dyn_cast<ConstantExpr>(gv->getInitializer()->getOperand(i))) {
        Value *gep_source = gep->getOperand(0);
        if (std::find(unsafe_globals.begin(), unsafe_globals.end(),
                      gep_source)) {
          int pos = std::distance(unsafe_globals.begin(),
                                  std::find(unsafe_globals.begin(),
                                            unsafe_globals.end(), gep_source));
          std::tuple<Value *, int, Value *> tuple;
          tuple = std::make_tuple(gv, i, paced_globals[pos]);
          global_init_replacement.insert(tuple);
        }
      }
    }
  }
}

void CryptSanLegacyPass::protectGlobals(
    Module &M, std::set<std::tuple<Value *, Value *, Value *>> &global_pairs) {
  std::vector<Value *> globals;
  for (Module::global_iterator it = M.global_begin(), ite = M.global_end();
       it != ite; ++it) {

    GlobalVariable *gv = dyn_cast<GlobalVariable>(it);

    // Global Variables need be 4 Byte aligned to mache shadow alignment
    GlobalVariable *Global = dyn_cast<GlobalVariable>(gv);
    Global->setAlignment(Align(4));

    if (!gv) {
      continue;
    }

    if (gv->getSection() == "llvm.metadata") {
      continue;
    }
    if (gv->getName() == "llvm.global_ctors") {
      continue;
    }

    if (gv->isConstant()) {
      bool addressTaken = false;
      for (auto &UI : gv->uses()) {
        auto user = UI.getUser();
        if (dyn_cast<StoreInst>(user)) {
          addressTaken = true;
        }
        if (!addressTaken) {
          continue;
        }
      }
    }

    bool canTransform = true;
    for (const Use &UI : gv->uses()) {
      auto user = UI.getUser();
      if (!(dyn_cast<Instruction>(user)) || (dyn_cast<PHINode>(user))) {
        // canTransform = false;
      }
    }
    if (!canTransform) {
      continue;
    }

    if (gv->uses().empty()) {
      continue;
    }

    if (!gv->hasInitializer())
      continue;

    bool AlwaysSafelyAccessed = true;
    SmallVector<const Instruction *> maybeSafeInsts;
    for (Function &F : M) {
      if (!isInterestingFunction(&F)) {
        continue;
      }

      TLI = TM->getSubtargetImpl(F)->getTargetLowering();

      auto &TLI = getAnalysis<TargetLibraryInfoWrapperPass>().getTLI(F);
      auto &ACT = getAnalysis<AssumptionCacheTracker>().getAssumptionCache(F);
      DominatorTree DT(F);
      LoopInfo LI(DT);
      ScalarEvolution SE(F, TLI, ACT, DT, LI);
      PointerType *gvar = dyn_cast<PointerType>(gv->getType());
      Type *Ty = gvar->getElementType();
      uint64_t Size = DL->getTypeAllocSize(Ty);

      if (!IsSafeGlobal(SE, gv, Size, maybeSafeInsts)) {
        AlwaysSafelyAccessed = false;
      }
    }

    if (AlwaysSafelyAccessed) {
      for (auto I : maybeSafeInsts) {
        SafeLoadStores.insert(I);
      }
      continue;
    }

    globals.push_back(gv);
    nr_of_gv_replaced++;
  }
  for (auto gv : globals) {

    // Create Second Globals which will contain the paced address of the
    // original
    PointerType *gvar = dyn_cast<PointerType>(gv->getType());
    Type *Ty = gvar->getElementType();
    uint64_t TySize = DL->getTypeAllocSize(Ty);

    llvm::Constant *Size = llvm::ConstantInt::get(Int32Ty, TySize, false);
    GlobalVariable *paced_gv = new GlobalVariable(
        /*Module=*/M,
        /*Type=*/PtrTy,
        /*isConstant=*/false,
        /*Linkage=*/GlobalValue::PrivateLinkage,
        /*Initializer=*/0, "__pac_" + Twine(gv->getName())
        /*Name=*/);
    paced_gv->setAlignment(
        llvm::Align(M.getDataLayout().getABITypeAlignment(PtrTy)));

    // Constant Definitions
    ConstantPointerNull *const_ptr_2 =
        ConstantPointerNull::get(dyn_cast<PointerType>(PtrTy));

    // Global Variable Definitions
    paced_gv->setInitializer(const_ptr_2);

    std::tuple<Value *, Value *, Value *> tuple;
    GlobalReplacement_map[gv] = paced_gv;
    tuple = std::make_tuple(gv, paced_gv, Size);

    global_pairs.insert(tuple);
  }
}

bool CryptSanLegacyPass::transformAllocasStack(Function *F,
                                               ScalarEvolution &SE) {
  if (!F)
    return false;

  StringRef Name = GlobalValue::dropLLVMManglingEscape(F->getName());
  // Ignore functions inserted by the compiler (this includes intrinsics).
  if (Name.startswith("llvm."))
    return false;
  // Ignore functions inserted by this pass.
  if (Name.startswith(kCryptSanFnPrefix))
    return false;
  // Ignore functions that are instrumented anyways.
  if (isUninstrumentedFunction(*F))
    return false;

  bool Changed = false;
  bool restart = false;
  inst_iterator I = inst_begin(F), E = inst_end(F);
  int remaining = std::distance(I, E);
  std::vector<Value *> need_free = {};

  while (remaining) {
    if (AllocaInst *AI = dyn_cast<AllocaInst>(&*I)) {

      nr_of_stack_variables++;
      Instruction *cryptsan_malloc;
      IRBuilder<> Builder(AI);
      Builder.SetInsertPoint(AI->getNextNode());
      auto tempI = AI->getNextNode();
      while (!Builder.getCurrentDebugLocation()) {
        tempI = tempI->getNextNode();
        Builder.SetCurrentDebugLocation(tempI->getDebugLoc());
      }
      uint64_t Size = getStaticAllocaAllocationSize(AI);

      SmallVector<const Instruction *> maybeSafeInsts;
      if (!IsSafeStackAlloca(SE, AI, Size, maybeSafeInsts) &&
          !(std::find(mainArgAllocas.begin(), mainArgAllocas.end(), AI) !=
            mainArgAllocas.end())) {
        nr_of_transformed_variables++;
        LLVM_DBG(dbgs() << "AI " << *AI << "\n");
        if (AI->isStaticAlloca()) {
          llvm::Constant *malloc_size =
              llvm::ConstantInt::get(Int64Ty, Size, false);
          LLVM_DBG(dbgs() << "Size " << Size << "\n");
          assert(Size && "Need Size > 0 on Alloca");
          auto CryptSanInitStackVariableFn =
              AI->getParent()->getParent()->getParent()->getOrInsertFunction(
                  "__cryptsan_init_stack_variable",
                  FunctionType::get(PtrTy, {AI->getType(), Int64Ty}, false));
          cryptsan_malloc = Builder.CreateCall(CryptSanInitStackVariableFn,
                                               {AI, malloc_size});
          Builder.SetInstDebugLocation(cryptsan_malloc);
        } else {
          Value *ArraySize = AI->getArraySize();
          if (ArraySize->getType() != Int64Ty)
            ArraySize = Builder.CreateIntCast(ArraySize, Int64Ty, false);

          Type *Ty = AI->getAllocatedType();
          uint64_t TySize = DL->getTypeAllocSize(Ty);
          Value *DynSize =
              Builder.CreateMul(ArraySize, ConstantInt::get(Int64Ty, TySize));
          auto CryptSanInitStackVariableFn =
              AI->getParent()->getParent()->getParent()->getOrInsertFunction(
                  "__cryptsan_init_stack_variable",
                  FunctionType::get(PtrTy, {AI->getType(), Int64Ty}, false));
          cryptsan_malloc =
              Builder.CreateCall(CryptSanInitStackVariableFn, {AI, DynSize});
          Builder.SetInstDebugLocation(cryptsan_malloc);
        }
        need_free.push_back(cryptsan_malloc);
        std::string new_name;
        new_name.append("m_");
        new_name.append(AI->getName().data());
        Value *cast_inst =
            Builder.CreateBitCast(cryptsan_malloc, AI->getType(), new_name);
        LLVM_DBG(dbgs() << "Replaced alloca " << *AI << " with malloc "
                        << *cryptsan_malloc << "\n");
        AI->replaceAllUsesWith(cast_inst);

        // Align to shadow metadata size
        if (AI->getAlignment() < 4) {
          AI->setAlignment(Align(4));
        }
        cryptsan_malloc->replaceUsesOfWith(cast_inst, AI);
        nr_of_allocas_replaced++;
        restart = true;
      } else {
        // For Safe allocas we can add all loads and stores to the
        // SafeLoadStore
        for (auto I : maybeSafeInsts) {
          SafeLoadStores.insert(I);
        }
      }
    } else if (ReturnInst *RI = dyn_cast<ReturnInst>(&*I)) {
      LLVM_DBG(dbgs() << "RI " << *RI << "\n");

      IRBuilder<> Builder(RI);
      Builder.SetInsertPoint(RI);

      auto CryptSanInitStackVariableFn = F->getParent()->getOrInsertFunction(
          "__cryptsan_clear_stack_variable",
          FunctionType::get(VoidTy, {PtrTy}, false));
      for (auto need_free_element : need_free) {
        if (m_dominator_tree->dominates(need_free_element, RI)) {
          Builder.CreateCall(CryptSanInitStackVariableFn, {need_free_element});
        }
      }
      restart = true;
    }
    --remaining;
    ++I;

    if (restart) {
      Changed |= true;
      I = inst_begin(F);
      E = inst_end(F);
      int total = std::distance(I, E);
      int cont = total - remaining;
      std::advance(I, cont);
      restart = false;
    }
  }
  return Changed;
}

uint64_t
CryptSanLegacyPass::getStaticAllocaAllocationSize(const AllocaInst *AI) {
  uint64_t Size = DL->getTypeAllocSize(AI->getAllocatedType());
  if (AI->isArrayAllocation()) {
    auto C = dyn_cast<ConstantInt>(AI->getArraySize());
    if (!C)
      return 0;
    Size *= C->getZExtValue();
  }
  return Size;
}

bool CryptSanLegacyPass::IsSafeGlobal(
    ScalarEvolution &SE, const Value *GlobalVariable, uint64_t AllocaSize,
    SmallVectorImpl<const Instruction *> &LoadStores) {
  // Go through all uses of this alloca and check whether all accesses to
  // the allocated object are statically known to be memory safe and, hence,
  // the object can be placed on the safe stack.
  SmallPtrSet<const Value *, 16> Visited;
  SmallVector<const Value *, 8> WorkList;
  WorkList.push_back(GlobalVariable);

  // A DFS search through all uses of the alloca in bitcasts/PHI/GEPs/etc.
  while (!WorkList.empty()) {
    const Value *V = WorkList.pop_back_val();
    for (const Use &UI : V->uses()) {
      if (dyn_cast<const Instruction>(UI.getUser())) {
        auto I = cast<const Instruction>(UI.getUser());
        assert(V == UI.get());

        switch (I->getOpcode()) {
        case Instruction::Load:
          LoadStores.push_back(I);
          if (!IsAccessSafe(SE, UI, DL->getTypeStoreSize(I->getType()),
                            GlobalVariable, AllocaSize))
            return false;
          break;

        case Instruction::VAArg:
          // "va-arg" from a pointer is safe.
          break;
        case Instruction::Store:
          LoadStores.push_back(I);
          if (V == I->getOperand(0)) {
            // Stored the pointer - conservatively assume it may be unsafe.
            LLVM_DBG(dbgs()
                     << "[SafeGV] Unsafe GV: " << *GlobalVariable
                     << "\n            store of address: " << *I << "\n");
            return false;
          }

          if (!IsAccessSafe(SE, UI,
                            DL->getTypeStoreSize(I->getOperand(0)->getType()),
                            GlobalVariable, AllocaSize))
            return false;
          break;

        case Instruction::Ret:
          // Information leak.
          return false;

        case Instruction::Call:
        case Instruction::Invoke: {
          const CallBase &CS = *cast<CallBase>(I);

          if (I->isLifetimeStartOrEnd())
            continue;

          if (const MemIntrinsic *MI = dyn_cast<MemIntrinsic>(I)) {
            if (!IsMemIntrinsicSafe(SE, MI, UI, GlobalVariable, AllocaSize)) {
              LLVM_DBG(dbgs()
                       << "[SafeGV] Unsafe GV: " << *GlobalVariable
                       << "\n            unsafe memintrinsic: " << *I << "\n");
              return false;
            }
            continue;
          }

          auto B = CS.arg_begin(), E = CS.arg_end();
          for (auto A = B; A != E; ++A)
            if (A->get() == V)
              if (!(CS.doesNotCapture(A - B) &&
                    (CS.doesNotAccessMemory(A - B) ||
                     CS.doesNotAccessMemory()))) {
                LLVM_DBG(dbgs() << "[SafeGV] Unsafe GV: " << *AllocaPtr
                                << "\n            unsafe call: " << *I << "\n");
                return false;
              }
          continue;
        }

        default:
          if (Visited.insert(I).second)
            WorkList.push_back(cast<const Instruction>(I));
        }
      } else {
        return false;
      }
    }
  }

  return true;
}

bool CryptSanLegacyPass::IsSafeStackAlloca(
    ScalarEvolution &SE, const Value *AllocaPtr, uint64_t AllocaSize,
    SmallVectorImpl<const Instruction *> &LoadStores) {
  // Go through all uses of this alloca and check whether all accesses to
  // the allocated object are statically known to be memory safe and, hence,
  // the object can be placed on the safe stack.
  SmallPtrSet<const Value *, 16> Visited;
  SmallVector<const Value *, 8> WorkList;
  WorkList.push_back(AllocaPtr);

  // A DFS search through all uses of the alloca in bitcasts/PHI/GEPs/etc.
  while (!WorkList.empty()) {
    const Value *V = WorkList.pop_back_val();
    for (const Use &UI : V->uses()) {
      auto I = cast<const Instruction>(UI.getUser());
      assert(V == UI.get());

      switch (I->getOpcode()) {
      case Instruction::Load:
        LoadStores.push_back(I);
        if (!IsAccessSafe(SE, UI, DL->getTypeStoreSize(I->getType()), AllocaPtr,
                          AllocaSize))
          return false;
        break;

      case Instruction::VAArg:
        // "va-arg" from a pointer is safe.
        break;
      case Instruction::Store:
        LoadStores.push_back(I);
        if (V == I->getOperand(0)) {
          // Stored the pointer - conservatively assume it may be unsafe.
          LLVM_DBG(dbgs() << "[SafeStack] Unsafe alloca: " << *AllocaPtr
                          << "\n            store of address: " << *I << "\n");
          return false;
        }

        if (!IsAccessSafe(SE, UI,
                          DL->getTypeStoreSize(I->getOperand(0)->getType()),
                          AllocaPtr, AllocaSize))
          return false;
        break;

      case Instruction::Ret:
        // Information leak.
        return false;

      case Instruction::Call:
      case Instruction::Invoke: {
        const CallBase &CS = *cast<CallBase>(I);

        if (I->isLifetimeStartOrEnd())
          continue;

        if (const MemIntrinsic *MI = dyn_cast<MemIntrinsic>(I)) {
          if (!IsMemIntrinsicSafe(SE, MI, UI, AllocaPtr, AllocaSize)) {
            LLVM_DBG(dbgs()
                     << "[SafeStack] Unsafe alloca: " << *AllocaPtr
                     << "\n            unsafe memintrinsic: " << *I << "\n");
            return false;
          }
          continue;
        }

        auto B = CS.arg_begin(), E = CS.arg_end();
        for (auto A = B; A != E; ++A)
          if (A->get() == V)
            if (!(CS.doesNotCapture(A - B) && (CS.doesNotAccessMemory(A - B) ||
                                               CS.doesNotAccessMemory()))) {
              LLVM_DBG(dbgs() << "[SafeStack] Unsafe alloca: " << *AllocaPtr
                              << "\n            unsafe call: " << *I << "\n");
              return false;
            }
        continue;
      }

      default:
        if (Visited.insert(I).second)
          WorkList.push_back(cast<const Instruction>(I));
      }
    }
  }

  return true;
}

bool CryptSanLegacyPass::IsAccessSafe(ScalarEvolution &SE, Value *Addr,
                                      uint64_t AccessSize,
                                      const Value *AllocaPtr,
                                      uint64_t AllocaSize) {
  AllocaOffsetRewriter Rewriter(SE, AllocaPtr);
  const SCEV *Expr = Rewriter.visit(SE.getSCEV(Addr));

  uint64_t BitWidth = SE.getTypeSizeInBits(Expr->getType());
  ConstantRange AccessStartRange = SE.getUnsignedRange(Expr);
  ConstantRange SizeRange =
      ConstantRange(APInt(BitWidth, 0), APInt(BitWidth, AccessSize));
  ConstantRange AccessRange = AccessStartRange.add(SizeRange);
  ConstantRange AllocaRange =
      ConstantRange(APInt(BitWidth, 0), APInt(BitWidth, AllocaSize));
  bool Safe = AllocaRange.contains(AccessRange);

  return Safe;
}

bool CryptSanLegacyPass::IsMemIntrinsicSafe(ScalarEvolution &SE,
                                            const MemIntrinsic *MI,
                                            const Use &U,
                                            const Value *AllocaPtr,
                                            uint64_t AllocaSize) {
  if (auto MTI = dyn_cast<MemTransferInst>(MI)) {
    if (MTI->getRawSource() != U && MTI->getRawDest() != U)
      return true;
  } else {
    if (MI->getRawDest() != U)
      return true;
  }

  const auto *Len = dyn_cast<ConstantInt>(MI->getLength());
  if (!Len)
    return false;
  return IsAccessSafe(SE, U, Len->getZExtValue(), AllocaPtr, AllocaSize);
}

void CryptSanLegacyPass::initializeFunctionDefinitionList(Module &M) {
  for (auto &F : M) {
    if (!F.isDeclaration())
      FunctionDefintionSet.insert(F.getGUID());
  }
}

// Instrument memset/memmove/memcpy
bool CryptSanLegacyPass::instrumentMemIntrinsic(Instruction *MI) {
  IRBuilder<> IRB(MI);
  if (isa<MemTransferInst>(MI)) {
    IRB.CreateCall(
        isa<MemMoveInst>(MI) ? CryptSanMemmoveFn : CryptSanMemcpyFn,
        {IRB.CreatePointerCast(MI->getOperand(0), IRB.getInt8PtrTy()),
         IRB.CreatePointerCast(MI->getOperand(1), IRB.getInt8PtrTy()),
         IRB.CreateIntCast(MI->getOperand(2), IntptrTy, false)});
    MI->eraseFromParent();
    return true;
  } else if (isa<MemSetInst>(MI)) {
    IRB.CreateCall(
        CryptSanMemsetFn,
        {IRB.CreatePointerCast(MI->getOperand(0), IRB.getInt8PtrTy()),
         IRB.CreateIntCast(MI->getOperand(1), IRB.getInt32Ty(), false),
         IRB.CreateIntCast(MI->getOperand(2), IntptrTy, false)});
    MI->eraseFromParent();
    return true;
  }
  return false;
}

bool CryptSanLegacyPass::isInterestingLoad(const LoadInst *LI) {
  Type *type_p = LI->getPointerOperandType();

  return isDereferencableType(type_p);
}

bool CryptSanLegacyPass::isDereferencableType(Type *type_p) {
  if (!(type_p->isStructTy() || type_p->isArrayTy() || type_p->isVectorTy() ||
        type_p->isPointerTy())) {
    return false;
  }
  return true;
}

bool CryptSanLegacyPass::isInterestingStore(const StoreInst *SI) {
  const Value *PtrOperand = SI->getPointerOperand();
  Type *Ty = cast<PointerType>(PtrOperand->getType()->getScalarType());
  if (Ty->getPointerAddressSpace() != 0)
    return false;

  if (PtrOperand->isSwiftError())
    return false;

  return isDereferencableType(Ty);
}

bool CryptSanLegacyPass::isInterestingFunction(const Function *F) {
  if (F->isDeclaration())
    return false;
  if (F->getName().startswith("llvm."))
    return false;
  if (F->getName().startswith(kCryptSanCtorPrefix) ||
      F->getName().startswith(kCryptSanFnPrefix))
    return false;
  return true;
}

bool CryptSanLegacyPass::CallNeedsInstrumentation(const CallBase *CI) {
  if (!CI)
    return false;

  if (CI->isIndirectCall()) {
    return false;
  }

  if (!CI->getCalledFunction())
    return false;

  const Function *F = dyn_cast<Function>(CI->getCalledFunction());

  if (!F) {
    LLVM_DBG(dbgs() << "Cannot instrument call " << *CI << '\n');
    return false;
  }

  if (F->getName().str().rfind("llvm.experimental.vector.reduce.add", 0) == 0)
    return false; // skip this for now
  if (F->getName().startswith(kCryptSanPrefix)) {
    return false; // one of our functions
  }
  bool foundFunction =
      std::find(FunctionDefintionSet.begin(), FunctionDefintionSet.end(),
                F->getGUID()) != FunctionDefintionSet.end();

  if (foundFunction) {
    return false;
  }
  return true;
}

Instruction *CryptSanLegacyPass::getNextInstruction(Instruction *I) {
  if (I->isTerminator()) {
    return I;
  } else {
    return I->getNextNode();
  }
}

bool CryptSanLegacyPass::runOnModule(Module &M) {
  dbgs() << "## CryptSanLegacyPass::runOnModule " << M.getName() << " ##\n";

  bool Changed = false;

  std::set<std::tuple<Value *, Value *, Value *>> global_pairs;
  std::set<std::tuple<Value *, int, Value *>> globals_init_replacements;
#ifdef PAC_GLOBALS
  protectGlobals(M, global_pairs);
  initGlobalsInGlobals(M, global_pairs, globals_init_replacements);

#endif

#ifdef PAC_PERSONALITY
  instrumentPersonalityFunctions(M);
#endif

  createCtorAndInitFunctions(M);
  initializeCallbacks(M);
  initializeFunctionDefinitionList(M);

  for (auto &F : M) {
    redirectLibFunction(&F);
  }

#ifdef PAC_GLOBALS
  // Replace uses of the global variable with loads from mirrored global
  // variable (paced version)

  for (auto gv_pair : GlobalReplacement_map) {

    GlobalVariable *gv = dyn_cast<GlobalVariable>(gv_pair.first);

    SmallVector<Instruction *, 4> Users;
    SmallVector<Constant *, 4> ConstUsers;
    for (auto *U : gv->users()) {
      // dbgs() << "gv_users " << *U << "\n";
      if (dyn_cast<Instruction>(U)) {
        Users.push_back(cast<Instruction>(U));
      } else {
        if (auto cons = dyn_cast<Constant>(U)) {
          ConstUsers.push_back(cast<Constant>(U));
        }
      }
    }

    for (auto *user : Users) {
      if (auto I = dyn_cast<Instruction>(user)) {
        IRBuilder<> Builder(I);
        auto tempI = I;
        while (!Builder.getCurrentDebugLocation()) {
          tempI = tempI->getNextNode();
          Builder.SetCurrentDebugLocation(tempI->getDebugLoc());
        }
        auto PACed_ptr = Builder.CreateLoad(GlobalReplacement_map[gv]);
        Value *CastedPACed_ptr = Builder.CreatePointerCast(
            PACed_ptr, gv->getType(), "_pac_gv" + Twine(gv->getName()));
        I->replaceUsesOfWith(gv, CastedPACed_ptr);
      }
    }

    for (auto *user : ConstUsers) {
      if (auto *CExpr = dyn_cast<ConstantExpr>(user)) {
        SmallVector<Instruction *, 4> UsersConsts;
        for (auto *use : CExpr->users()) {
          if (Instruction *I = dyn_cast<Instruction>(use)) {
            UsersConsts.push_back(I);
          }
        }
        for (auto *I : UsersConsts) {
          Instruction *CI = CExpr->getAsInstruction();
          IRBuilder<> Builder(I);
          auto PACed_ptr = Builder.CreateLoad(GlobalReplacement_map[gv]);

          Value *CastedPACed_ptr = Builder.CreatePointerCast(
              PACed_ptr, gv->getType(), "_pac_gv" + Twine(gv->getName()));
          // CExpr->replaceAllUsesWith(CastedPACed_ptr);
          Builder.Insert(CI);
          CI->replaceUsesOfWith(gv, CastedPACed_ptr);
          I->replaceUsesOfWith(CExpr, CI);
        }
      }
    }
  }

  // Init global variable that contains PACed version of global
  bool globals_initialized = false;
  for (auto &F : M) {
    for (auto &BB : F) {
      StringRef Name = GlobalValue::dropLLVMManglingEscape(F.getName());
      if ((Name == "main") && !globals_initialized) {
        auto I = BB.getFirstNonPHI();
        IRBuilder<> Builder(I);
        auto tempI = I;
        while (!Builder.getCurrentDebugLocation()) {
          tempI = tempI->getNextNode();
          Builder.SetCurrentDebugLocation(tempI->getDebugLoc());
        }
        int j = 0;
        for (auto pair : global_pairs) {
          Value *CastedGV = Builder.CreatePointerCast(std::get<0>(pair), PtrTy);
          Value *ValueID = ConstantInt::get(Int32Ty, j);
          Value *args[] = {ValueID, CastedGV, std::get<1>(pair),
                           std::get<2>(pair)};
          j++;
          Builder.CreateCall(CryptSanInitGlobalWithNameFn, args);
        }
        globals_initialized = true;

        for (auto &replace : globals_init_replacements) {
          auto gv = std::get<0>(replace);
          auto Index = std::get<1>(replace);
          auto unsafe_gv = std::get<2>(replace);
          Value *Target = Builder.CreateStructGEP(gv, Index);
          Value *paced_unsafe_gv = Builder.CreateLoad(unsafe_gv);
          Value *CastedTarget = Builder.CreatePointerCast(
              Target, paced_unsafe_gv->getType()->getPointerTo());
          Builder.CreateStore(paced_unsafe_gv, CastedTarget);
        }
      }
    }
  }
#endif

  bool argv_initalized = false;
  for (auto &F : M) {
    for (auto &BB : F) {
      StringRef Name = GlobalValue::dropLLVMManglingEscape(F.getName());
      if ((Name == "main") && !argv_initalized) {
        argv_initalized = true;
        auto I = BB.getFirstNonPHI();
        IRBuilder<> Builder(I);
        auto tempI = I;
        while (!Builder.getCurrentDebugLocation()) {
          tempI = tempI->getNextNode();
          Builder.SetCurrentDebugLocation(tempI->getDebugLoc());
        }
        for (auto &A : F.args()) {
          for (auto &Use : A.uses()) {
            if (auto Ins = dyn_cast<StoreInst>(Use.getUser())) {
              mainArgAllocas.push_back(Ins->getOperand(1));
              Builder.SetInsertPoint(Ins->getNextNonDebugInstruction());
            }
          }
        }
        if (mainArgAllocas.size() == 2) {
          Builder.CreateCall(CryptSanInitMainArgsFn, mainArgAllocas);
        } else if (mainArgAllocas.size() == 3) {
          assert(0 && "Handle 3 arg main function\n");
        }
      }
    }
  }

  for (Function &F : M) {

    SkippablePointers = {};
    NotSkippablePointers = {};

    if (!isInterestingFunction(&F)) {
      LLVM_DBG(dbgs() << "Skipping " << F.getName() << "\n");
      continue;
    }
    TLI = TM->getSubtargetImpl(F)->getTargetLowering();

    auto &TLI = getAnalysis<TargetLibraryInfoWrapperPass>().getTLI(F);
    auto &ACT = getAnalysis<AssumptionCacheTracker>().getAssumptionCache(F);
    DominatorTree DT(F);
    m_dominator_tree = &DT;
    LoopInfo LI(DT);
    ScalarEvolution SE(F, TLI, ACT, DT, LI);
#ifdef STACK_PROTECT
    Changed |= transformAllocasStack(&F, SE);
#endif /* STACK_PROTECT */

    SmallVector<LoadInst *, 32> Loads;
    SmallVector<StoreInst *, 32> Stores;
    SmallVector<Instruction *, 2> MemIntrinsics;

    std::map<Value *, Value *> FDCE_map;
    std::map<Value *, Value *> FTCE_map;
    std::map<Value *, Value *> auted_map;
    std::map<Value *, int> StrippableMap;

    std::map<Value *, uint64_t> insert_end_check_map;
    std::map<Value *, Value *> rangeAuted;

    bbDerefCheck(F, FDCE_map);

    unsigned long checks = 0;
    for (auto &BB : F) {
      for (auto &I : BB) {
        if (LoadInst *LI = dyn_cast<LoadInst>(&I)) {
          Value *pointeroperand = LI->getPointerOperand();
          checks++;
          findRedundantChecks(&I, StrippableMap, pointeroperand, false);
        } else if (StoreInst *SI = dyn_cast<StoreInst>(&I)) {
          Value *pointeroperand = SI->getPointerOperand();
          checks++;
          findRedundantChecks(&I, StrippableMap, pointeroperand, false);
        }
      }
    }

    for (auto I : SafeLoadStores) {
      if (const LoadInst *LI = dyn_cast<const LoadInst>(I)) {
        SkippablePointers.insert(LI->getPointerOperand());
      } else if (const StoreInst *SI = dyn_cast<const StoreInst>(I)) {
        SkippablePointers.insert(SI->getPointerOperand());
      }
    }

    bbSameLockCheck(F, FTCE_map);

    bool restart = false;
    inst_iterator It = inst_begin(F), E = inst_end(F);
    int remaining = std::distance(It, E);
    while (remaining) {
      IRBuilder<> Builder(&*It);
      auto &I = *It;
      if (isa<MemIntrinsic>(I)) {
        LLVM_DBG(dbgs() << "MI" << I << "\n");
        restart = instrumentMemIntrinsic(&I);
      } else if (CallBase *CI = dyn_cast<CallBase>(&I)) {
        if (CallNeedsInstrumentation(CI)) {
          for (unsigned i = 0; i < CI->getNumOperands(); i++) {
            Value *pointeroperand = CI->getOperand(i);
            Type *poType = pointeroperand->getType();
            if (poType->isPointerTy()) {
              if (!canSkipPointer(pointeroperand,
                                  std::vector<const Value *>{})) {
                LLVM_DBG(dbgs() << "CI" << *CI << "\n");
                // Value *V = forceAutPointer(CI, pointeroperand);
                Value *V = stripPointer(CI, pointeroperand);
                LLVM_DEBUG(dbgs() << "V " << *V << "\n");
                CI->setOperand(i, V);
                restart = true;
              }
            }
          }
          if (CI->getType()->isPointerTy()) {
            applyMask(CI);
            restart = true;
          }
        }
      } else if (LoadInst *LI = dyn_cast<LoadInst>(&I)) {
        if (isInterestingLoad(LI)) {
          if (!canSkipPointer(LI->getPointerOperand(),
                              std::vector<const Value *>{})) {
            Value *po = LI->getPointerOperand();
#ifdef OPTIMIZE_FDCE
            if (FDCE_map.count(LI) && auted_map.count(FDCE_map[LI])) {
              Value *V = auted_map[FDCE_map[LI]];
              LLVM_DBG(dbgs() << "Skipping " << *LI << " for " << *V << "\n");
              LI->setOperand(0, V);
              restart = true;
            } else if (StrippableMap.count(LI)) {
              Value *V = stripPointer(LI, po);
              LLVM_DBG(dbgs() << "V" << *V << "\n");
              LI->setOperand(0, V);
              restart = true;
            } else
#endif
#ifdef OPTIMIZE_FTCE
                if (FTCE_map.count(LI) && auted_map.count(FTCE_map[LI]) &&
                    AutedID_map.count(FTCE_map[LI])) {
              dbgs() << "count " << *AutedID_map[FTCE_map[LI]] << "\n";
              Value *compId = AutedID_map[FTCE_map[LI]];
              Value *V = autByIdPointer(LI, po, compId);
              LI->setOperand(0, V);
              restart = true;
            } else
#endif
            {
              nr_of_instrumented_loads++;
              Value *V = forceAutPointer(LI, po);
              auted_map[LI] = V;
              LLVM_DBG(dbgs() << "V" << *V << "\n");
              LI->setOperand(0, V);
              restart = true;
            }
          }
        }
      } else if (StoreInst *SI = dyn_cast<StoreInst>(&I)) {
        if (isInterestingStore(SI)) {
          if (!canSkipPointer(SI->getPointerOperand(),
                              std::vector<const Value *>{})) {

            Value *po = SI->getPointerOperand();
#ifdef OPTIMIZE_FDCE
            if (FDCE_map.count(SI) && auted_map.count(FDCE_map[SI])) {
              Value *V = auted_map[FDCE_map[SI]];
              LLVM_DBG(dbgs() << "Skipping " << *SI << " for " << *V << "\n");
              SI->setOperand(1, V);
              restart = true;
            } else if (StrippableMap.count(SI)) {
              Value *V = stripPointer(SI, po);
              LLVM_DBG(dbgs() << "V" << *V << "\n");
              SI->setOperand(1, V);
              restart = true;
            } else
#endif
#ifdef OPTIMIZE_FTCE
                if (FTCE_map.count(SI) && auted_map.count(FTCE_map[SI]) &&
                    AutedID_map.count(FTCE_map[SI])) {
              Value *compId = AutedID_map[FTCE_map[SI]];
              Value *V = autByIdPointer(SI, po, compId);
              SI->setOperand(1, V);
              restart = true;
            } else
#endif
            {
              nr_of_instrumented_stores++;
              Value *V = forceAutPointer(SI, po);
              auted_map[SI] = V;
              LLVM_DBG(dbgs() << "V" << *V << "\n");
              SI->setOperand(1, V);
              restart = true;
            }
          }
        }
      }
      --remaining;
      ++It;
      if (restart) {
        It = inst_begin(F);
        E = inst_end(F);
        int total = std::distance(It, E);
        int cont = total - remaining;
        std::advance(It, cont);
        restart = false;
        Changed |= true;
      }
    }
  }
  return Changed;
}

ModulePass *llvm::createCryptSanLegacyPass(const TargetMachine *TM) {
  return new CryptSanLegacyPass(TM);
}