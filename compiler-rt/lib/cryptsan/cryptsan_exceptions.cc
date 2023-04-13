//===-- cryptsan_exceptions.cpp ---------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of CryptSan.
//
// CryptSan runtime.
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_common.h"
#include "cryptsan.h"
#include <unwind.h>
using namespace __cryptsan;
using namespace __sanitizer;

typedef _Unwind_Reason_Code PersonalityFn(int version, _Unwind_Action actions,
                                          uint64_t exception_class,
                                          _Unwind_Exception *unwind_exception,
                                          _Unwind_Context *context);

// Pointers to the _Unwind_GetGR and _Unwind_GetCFA functions are passed in
// instead of being called directly. This is to handle cases where the unwinder
// is statically linked and the sanitizer runtime and the program are linked
// against different unwinders. The _Unwind_Context data structure is opaque so
// it may be incompatible between unwinders.
#if defined(__APPLE__)
#else
typedef _Unwind_Word GetGRFn(_Unwind_Context *context, int index);
typedef _Unwind_Word GetCFAFn(_Unwind_Context *context);

extern "C" SANITIZER_INTERFACE_ATTRIBUTE _Unwind_Reason_Code
__cryptsan_personality_wrapper(int version, _Unwind_Action actions,
                              uint64_t exception_class,
                              _Unwind_Exception *unwind_exception,
                              _Unwind_Context *context,
                              PersonalityFn *real_personality, GetGRFn *get_gr,
                              GetCFAFn *get_cfa)
{
  _Unwind_Reason_Code rc;
  if (real_personality)
    rc = real_personality(version, actions, exception_class, unwind_exception,
                          context);
  else
    rc = _URC_CONTINUE_UNWIND;
  if ((actions & _UA_CLEANUP_PHASE) && rc == _URC_CONTINUE_UNWIND)
  {
#if defined(__aarch64__)
    uptr fp = get_gr(context, 29); // x29
#else
#error Unsupported architecture
#endif
    uptr sp = get_cfa(context);
    size_t size = fp - sp;
    CRYPTSAN_DEBUG("__cryptsan_personality_wrapper_untag from %p to %p", fp, sp);
    unsigned int id = 0;
    poms_add((uptr *)sp, id, size);
  }

  return rc;
}
#endif
