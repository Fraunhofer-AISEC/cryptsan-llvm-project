//===-- cryptsan_stacktrace.cc ---------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of CryptSan.
//
// CryptSan stack trace.
//===----------------------------------------------------------------------===//
#include "cryptsan/cryptsan.h"

#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_stacktrace.h"

namespace __cryptsan {

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void print_stack_trace() {
  uptr top = 0;
  uptr bottom = 0;

  bool request_fast_unwind = common_flags()->fast_unwind_on_fatal;
#if SANITIZER_MAC ||  SANITIZER_IOS
  request_fast_unwind = true;
#endif
  if (request_fast_unwind)
    __sanitizer::GetThreadStackTopAndBottom(false, &top, &bottom);
  Printf("Thread top and bottom: %p, %p", top, bottom);

  GET_CURRENT_PC_BP_SP;
  (void)sp;
  BufferedStackTrace stack;
  stack.Unwind(kStackTraceMax, pc, bp, nullptr, top, bottom, request_fast_unwind);
  stack.Print();
}

}
