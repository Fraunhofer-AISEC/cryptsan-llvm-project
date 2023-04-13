//===-- pacinst.cc ---------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of CryptSan.
//
// PAC API
//===----------------------------------------------------------------------===//
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <wchar.h>
#include <assert.h>
#include "cryptsan.h"

//#define SIM

void *__cryptsan_xpac(void *ptr);
void *__cryptsan_aut_by_id(void *ptr, unsigned long ref_id);
void *__cryptsan_pacda(void *ptr, unsigned id);
void *__cryptsan_autda(void *ptr, unsigned id);
typedef unsigned long uptr;
typedef unsigned int u32;

void __cryptsan_error_handler() {
    assert(0);
}

void __cryptsan_clear_stack_variable(uptr *ptr)
  {
    ptr = (uptr *)((unsigned long) ptr & PAC_STRIP_MASK);
    u32 *MetadataPtr = (u32 *)poms_ptr(ptr);
    u32 id = *MetadataPtr;

    if (id != 0)
    {
      while (*MetadataPtr == id)
      {
        *MetadataPtr++ = 0;
      }
    }
  }

__attribute__((always_inline)) uint64_t __cryptsan_combine_tag_with_address(uint64_t ptr_tag, uint64_t ptr_address)
{
    asm(
        "bfxil  %x0, %x1, #0, #43\n"
        : "+r"(ptr_tag)
        : "r"(ptr_address));
    return ptr_tag;
}

__attribute__((always_inline)) void *__cryptsan_xpac(void *ptr)
{
#ifdef SIM
    return (void *)((long)ptr & 0x000000FFFFFFFFFFFULL);
#else
    void *retPtr = ptr;
    asm(
        "xpacd %x0\n"
        : "+r"(retPtr)
        :);
    return retPtr;
#endif
}

__attribute__((always_inline)) void *__cryptsan_pacda(void *ptr, unsigned id)
{
#ifdef SIM
    asm(
        "eor x0,x0,%x0\n"
        "eor x0,x0,%x0\n"
        :
        : "r"(id));
    return ptr;
#else
    void *retPtr = ptr;
    asm(
        "mov %x0,%0\n"
        :
        : "r"(retPtr));
    asm(
        "pacda %x0, %x1\n"
        : "=r"(retPtr)
        : "r"(id));
    return retPtr;

#endif
}

__WEAK_INLINE void *__cryptsan_autdza(void *ptr)
{
#ifdef SIM
    asm(
        "eor x0,x0,%x0\n"
        "eor x0,x0,%x0\n"
        :
        : "r"(ptr));
    return ptr;
#else
    asm(
        "mov %x0,%0\n"
        :
        : "r"(ptr));
    asm volatile(
        "autdza %x0\n"
        : "+r"(ptr));
    return ptr;
#endif
}

__WEAK_INLINE void __cryptsan_par_autdza(void *ptr)
{
#ifdef SIM
    asm(
        "eor x0,x0,%x0\n"
        "eor x0,x0,%x0\n"
        :
        : "r"(ptr));
#else
    asm volatile(
        "mov %x0,%0\n"
        :
        : "r"(ptr));
    asm volatile(
        "autdza %x0\n"
        : "+r"(ptr));
    if ((unsigned long)ptr & ERROR_MASK) {
        printf("__cryptsan_par_autdza error: 0x%llx\n", (unsigned long)ptr);
        __cryptsan_error_handler();
    }

#endif
}

__WEAK_INLINE void *__cryptsan_aut_by_id(void *ptr, unsigned long ref_id) {
    uptr *stripped = poms_strip_pac(ptr);
    stripped = align_to_word(stripped);
    u32 id = *poms_ptr(stripped);
    return (id == ref_id) ? stripped : ptr;
};



__WEAK_INLINE void *__cryptsan_force_aut(void *ptr) {
  uptr *stripped = poms_strip_pac(ptr);
    __cryptsan_aut_pointer(ptr);
    return stripped;    
}

__WEAK_INLINE void *__cryptsan_autda(void *ptr, unsigned id)
{
#ifdef SIM
    asm(
        "eor x0,x0,%x0\n"
        "eor x0,x0,%x0\n"
        :
        : "r"(id));
    return ptr;
#else
    asm(
        "mov %x0,%0\n"
        :
        : "r"(ptr));
    asm(
        "autda %x0, %x1\n"
        : "+r"(ptr)
        : "r"(id));
    return ptr;
#endif
}

