//===-- CryptSan.h ---------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of CryptSan.
//
// CryptSan Instrumentation Pass Class.
//===----------------------------------------------------------------------===//
#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_CRYPTSANSANITIZERPASS_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_CRYPTSANSANITIZERPASS_H

#include "llvm/IR/Function.h"
#include "llvm/IR/PassManager.h"
#include "llvm-c/Core.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/Hashing.h"
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

namespace llvm {

class CryptSanDummyPass : public ModulePass {
public:
  static char ID;
  const TargetMachine *TM = nullptr;
  CryptSanDummyPass(const TargetMachine *TargetM) : ModulePass(ID) {
    TM = TargetM;
  }
  StringRef getPassName() const override;
  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<TargetLibraryInfoWrapperPass>();
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<PostDominatorTreeWrapperPass>();

    // AU.addRequired<TargetPassConfig>();
    AU.addRequired<AssumptionCacheTracker>();
  }
  bool doInitialization(Module &M) override;
  bool runOnModule(Module &M) override;
};

class CryptSanLegacyPass : public ModulePass {
public:
  static char ID;
  const TargetMachine *TM = nullptr;

  CryptSanLegacyPass(const TargetMachine *TargetM) : ModulePass(ID) {
    TM = TargetM;
  }

  int nr_of_force_auts = 0;
  int nr_of_stack_variables = 0;
  int nr_of_transformed_variables = 0;
  int nr_of_heap_variables = 0;
  int nr_of_load_stores = 0;
  int nr_of_masks_applied = 0;
  int nr_of_gv_replaced = 0;
  int nr_of_instrumented_stores = 0;
  int nr_of_instrumented_loads = 0;
  int nr_of_allocas_replaced = 0;
  int nr_of_redundant_checks = 0;
  int nr_of_shared_lock_checks = 0;
  StringRef getPassName() const override;
  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<TargetLibraryInfoWrapperPass>();
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<PostDominatorTreeWrapperPass>();

    // AU.addRequired<TargetPassConfig>();
    AU.addRequired<AssumptionCacheTracker>();
  }
  bool doInitialization(Module &M) override;
  bool runOnModule(Module &M) override;

private:
  const DataLayout *DL;
  const TargetLowering *TLI = nullptr;
  LLVMContext *C;
  DominatorTree *m_dominator_tree;
  PostDominatorTree *m_post_dominator_tree;
  Function *MainCtorFn;
  FunctionCallee CryptSanMallocFn;
  FunctionCallee CryptSanMemsetFn;
  FunctionCallee CryptSanMemcpyFn;
  FunctionCallee CryptSanMemmoveFn;
  FunctionCallee CryptSanApplyMaskFn;
  FunctionCallee CryptSanInitMainArgsFn;
  FunctionCallee CryptSanFreeFn;
  FunctionCallee CryptSanCallocFn;
  FunctionCallee CryptSanReallocFn;
  FunctionCallee CryptSanAutIntrinsic;
  FunctionCallee CryptSanIDAutIntrinsic;
  FunctionCallee CryptSanAutFn;
  FunctionCallee CryptSanInitGlobalFn;
  FunctionCallee CryptSanInitGlobalWithNameFn;
  FunctionCallee CryptSanFreeStackVariableFn;
  FunctionCallee CryptSanDebugFn;
  Type *Int1Ty;
  Type *Int8Ty;
  Type *Int32Ty;
  Type *Int64Ty;
  Type *IntptrTy;
  Type *PtrTy;
  Type *DoublePtrTy;
  Type *TriplePtrTy;
  Type *Ptr32Ty;
  Type *Ptr64Ty;
  Type *VoidTy;
  std::set<llvm::GlobalValue::GUID> FunctionDefintionSet = {};
  std::set<const Value *> SkippablePointers = {};
  std::set<const Value *> AlwaysAutPointers = {};
  std::set<const Instruction *> SafeLoadStores = {};
  std::set<const Value *> NotSkippablePointers = {};
  std::map<Value *, Value *> AutedID_map;
  std::map<Value *, Value *> GlobalReplacement_map;
  SmallVector<Value *, 2> mainArgAllocas = {};
  void
  protectGlobals(Module &M,
                 std::set<std::tuple<Value *, Value *, Value *>> &global_pairs);
  void
  initGlobalsInGlobals(Module &M,
                 std::set<std::tuple<Value *, Value *, Value *>> &global_pairs,  std::set<std::tuple<Value *, int, Value *>> &global_init_replacement);
  bool postDominates(Instruction *A, Instruction *B);
  static bool isDereferencableType(Type *type_p);
  static bool getRecursivePointerArgs(Value *U, std::set<Value *> &set);
  static bool callHasDependentPointerArgs(CallBase *CB,
                                          Instruction *load_store);
  bool callInstBetween(Instruction *start, Instruction *end);
  void findRedundantChecks(Instruction *checked_load_store,
                           std::map<Value *, int> &FDCE_map,
                           Value *pointer_operand, bool goneThroughGEP);
  void initializeFunctionDefinitionList(Module &M);
  void initializeCallbacks(Module &M);
  bool checkLoadStoreSourceIsGEP(Instruction *load_store, Value *gep_source);
  bool instrumentMemIntrinsic(Instruction *I);
  bool isInterestingStore(const StoreInst *SI);
  bool isInterestingLoad(const LoadInst *LI);
  Instruction *getNextInstruction(Instruction *);
  bool CallNeedsInstrumentation(const CallBase *CI);
  void bbDerefCheck(Function &F, std::map<Value *, Value *> &FDCE_map);
  void bbSameLockCheck(Function &F, std::map<Value *, Value *> &FTCE_map);
  void redirectLibFunction(Function *F);
  bool canSkipPointer(const Value *pointeroperand,
                      std::vector<const Value *> AlreadyProcessed);
  PHINode *autPointer(Instruction *I, Value *pointeroperand);
  Value *forceAutPointer(Instruction *I, Value *pointeroperand);
  Value *autPointerAtOffset(Instruction *I, Value *pointeroperand, Value *Offset);
  void applyMask(Instruction *I);

  Value *stripPointer(Instruction *I, Value *pointeroperand);
  Value *autByIdPointer(Instruction *I, Value *pointeroperand, Value *ref_id);
  bool transformAllocasStack(Function *F, ScalarEvolution &SE);
  void createCtorAndInitFunctions(Module &M);
  uint64_t getStaticAllocaAllocationSize(const AllocaInst *AI);
  bool IsSafeStackAlloca(ScalarEvolution &SE, const Value *AllocaPtr,
                         uint64_t AllocaSize,
                         SmallVectorImpl<const Instruction *> &LoadStores);

  bool IsSafeGlobal(ScalarEvolution &SE, const Value *GlobalVariable,
                    uint64_t AllocaSize,
                    SmallVectorImpl<const Instruction *> &LoadStores);
  bool IsMemIntrinsicSafe(ScalarEvolution &SE, const MemIntrinsic *MI,
                          const Use &U, const Value *AllocaPtr,
                          uint64_t AllocaSize);
  bool IsAccessSafe(ScalarEvolution &SE, Value *Addr, uint64_t Size,
                    const Value *AllocaPtr, uint64_t AllocaSize);
  bool isInterestingFunction(const Function *F);
  void instrumentPersonalityFunctions(Module &M);
};
};

// FunctionPass *createHWAddressSanitizerLegacyPassPass();



#endif
