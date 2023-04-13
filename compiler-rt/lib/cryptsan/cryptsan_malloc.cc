//===-- cryptsan_malloc.cc ---------------------------------------------===//
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
#include "cryptsan/cryptsan.h"
#include "sanitizer_common/sanitizer_common.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if defined(__APPLE__)
#include <malloc/malloc.h>
#endif
#include <limits.h>
#include <wchar.h>
using namespace __cryptsan;
#define SIZE_ALIGN (4 * sizeof(uintptr_t))
#define SIZE_MASK (-SIZE_ALIGN)
#define OVERHEAD (2 * sizeof(size_t))

struct metadata
{
  uptr size;
};

uint32_t __cryptsan_get_next_id(void)
{
  static uint32_t id = 1;
  id++;
  if (id == 0)
  {
    id++;
  }

  return id;
}

void *__cryptsan_rt_malloc(size_t size)
{
  return __cryptsan_malloc(size);
}

void *__cryptsan_malloc(size_t size)
{
  CRYPTSAN_DEBUG("__cryptsan_malloc: Allocate %llu bytes", size);
  void *ptr;

  if ((ptr = malloc(size)))
  {
    if (size > 0)
    {
      if ((size < 4))
      {
        size = 4;
      }
      void *old_ptr = ptr;
      do
      {
        u32 id = __cryptsan_get_next_id();
        poms_add((uptr *)ptr, id, size);
        void *id_ptr = (void *)(u64)id;
        CRYPTSAN_DEBUG("PAC 0x%llx with id: 0x%llx", (unsigned long)ptr, (unsigned long)id);
#ifdef SIM
        asm volatile(
            "eor x0,x0,%x0\n"
            "eor x0,x0,%x0\n"
            "eor x0,x0,%x0\n"
            "eor x0,x0,%x0\n"
            :
            : "r"(id));
#else
        asm volatile(
            "pacdza %[input_ptr] \t\n"
            : "+r"(id_ptr) // mark as IN/OUT register
            : [input_ptr] "r"(id_ptr));
#endif
        ptr = combine(ptr, id_ptr);
      } while (
          ptr == old_ptr);
      CRYPTSAN_DEBUG("After PAC: 0x%llx", (unsigned long)ptr);
    }
    return ptr;
  }

  return nullptr;
}

void __cryptsan_report_error()
{
  abort("CryptSan: memory violation detected\n");
}

void *__cryptsan_aut_at_offset(const void *ptr, int offset)
{
  return __cryptsan_aut_pointer((char *)ptr + offset);
}

void *__cryptsan_aut_pointer(const void *ptr)
{
  uptr *stripped = poms_strip_pac(ptr);
  void *stripped2 = stripped;
  stripped = align_to_word(stripped);
  u32 id = *poms_ptr(stripped);
  u32 *id_ptr = (u32 *)(u64)id;
  void *aut_ptr = combine(id_ptr, ptr);
#ifdef SIM
  asm volatile(
      "eor x0,x0,%x0\n"
      "eor x0,x0,%x0\n"
      "eor x0,x0,%x0\n"
      "eor x0,x0,%x0\n"
      :
      : "r"(id));
#else
  asm volatile(
      "autdza %[input_ptr] \t\n"
      : "+r"(aut_ptr) // mark as IN/OUT register
      : [input_ptr] "r"(aut_ptr));
#endif
  void *test = combine(ptr, aut_ptr);

  CRYPTSAN_DEBUG("__cryptsan_aut_pointer 0x%llx: 0x%llx with id 0x%x at 0x%llx", (unsigned long)ptr, (unsigned long)aut_ptr, (unsigned long)id, poms_ptr(stripped));
  if ((unsigned long)test & ERROR_MASK)
  {
    CRYPTSAN_DEBUG("After authentication 0x%llx", (unsigned long)test);
    __cryptsan_report_error();
    return NULL;
  }
  else
  {
    return (void *)stripped2;
  }
}

void *__cryptsan_reapply_mask(const void *ptr)
{
  CRYPTSAN_DEBUG("__cryptsan_reapply_mask for 0x%llx ", (unsigned long)ptr);
    void *aligned = align_to_word(ptr); // align to 4 Byte, same as id
    u32 id = *poms_ptr(aligned);        // get pointer to meta data
    u32 *id_ptr = (u32 *)(u64)id;
#ifdef SIM
    asm volatile(
        "eor x0,x0,%x0\n"
        "eor x0,x0,%x0\n"
        "eor x0,x0,%x0\n"
        "eor x0,x0,%x0\n"
        :
        : "r"(id));
#else
    asm volatile(
        "pacdza %[input_ptr] \t\n"
        : "+r"(id_ptr) // mark as IN/OUT register
        : [input_ptr] "r"(id_ptr));
#endif
    uptr *mask = poms_get_mask(id_ptr);
    void *test = poms_apply_mask(ptr, mask);
    CRYPTSAN_DEBUG("Return 0x%llx", (unsigned long)test);
    return test;
}

void __cryptsan_free(void *ptr)
{
  CRYPTSAN_DEBUG("__cryptsan_free 0x%llx", (unsigned long)ptr);
  if (!ptr)
    return;
  ptr = __cryptsan_aut_pointer(ptr);
  uptr *id_ptr = poms_ptr(ptr);
  u32 id = *id_ptr;
  u32 prev_id = *(id_ptr - 1);
  if (id == prev_id)
  {
    CRYPTSAN_DEBUG("Freeing pointer inside buffer");
    __cryptsan_report_error();
  }
  poms_remove((uptr *)ptr, STATUS_FREED);
  free(ptr);
}

void *__cryptsan_calloc(uptr nmemb, size_t size)
{
  if (nmemb && size && SIZE_MAX / nmemb < size)
    return nullptr;
  void *ptr = __cryptsan_malloc(nmemb * size);
  memset(__cryptsan_aut_pointer(ptr), 0, nmemb * size);
  return ptr;
}

void *__cryptsan_realloc(void *ptr, size_t newSize)
{
  void *newPtr;
  if (ptr == 0)
  {
    return __cryptsan_malloc(newSize);
  }
#if defined(__APPLE__)
  unsigned int curSize;
  curSize = malloc_size(__cryptsan_aut_pointer(ptr));
  if (newSize <= curSize)
  {
    return ptr;
  }
  newPtr = __cryptsan_malloc(newSize);
  bcopy(__cryptsan_aut_pointer(ptr), __cryptsan_aut_pointer(newPtr), (int)curSize);
#else
  newPtr = __cryptsan_malloc(newSize);
  bcopy(__cryptsan_aut_pointer(ptr), __cryptsan_aut_pointer(newPtr), (int)newSize);
#endif
  return newPtr;
}

void *__cryptsan_memcpy(void *dest, const void *src, size_t len)
{
  CRYPTSAN_DEBUG("__cryptsan_memcpy with len %zu", len);
  void *tmp_dest = dest;
  if (check_autable(tmp_dest))
  {
    __cryptsan_aut_pointer((void *)((unsigned long)tmp_dest + len - 1));
    tmp_dest = __cryptsan_aut_pointer(tmp_dest);
  }
  if (check_autable(src))
  {
    __cryptsan_aut_pointer((void *)((unsigned long)src + len - 1));
    src = __cryptsan_aut_pointer(src);
  }
  memcpy(tmp_dest, src, len);
  return dest;
}

void *__cryptsan_memmove(void *dest, const void *src, size_t len)
{
  CRYPTSAN_DEBUG("__cryptsan_memcpy with len %zu", len);
  void *orig_dest = dest;
  if (check_autable(dest))
  {
    __cryptsan_aut_pointer((void *)((unsigned long)dest + len - 1));
    dest = __cryptsan_aut_pointer(dest);
  }
  if (check_autable(src))
  {
    __cryptsan_aut_pointer((void *)((unsigned long)src + len - 1));
    src = __cryptsan_aut_pointer(src);
  }
  memmove(dest, src, len);
  return orig_dest;
}

void *__cryptsan___memcpy_chk(void *dest, const void *src, size_t len, size_t dstlen)
{
  CRYPTSAN_DEBUG("__cryptsan___memcpy_chk with len %zu and dstlen %zu", len, dstlen);
  void *orig_dest = dest;
  if (dstlen < len)
    Die();
  if (check_autable(dest))
  {
    __cryptsan_aut_pointer((void *)((unsigned long)dest + len - 1));
    dest = __cryptsan_aut_pointer(dest);
  }
  if (check_autable(src))
  {
    __cryptsan_aut_pointer((void *)((unsigned long)src + len - 1));
    src = __cryptsan_aut_pointer(src);
  }
  memcpy(dest, src, len);
  return orig_dest;
}

void *__cryptsan_reallocarray(void *ptr, size_t nmemb, size_t size)
{
  if (nmemb && size && SIZE_MAX / nmemb < size)
    return nullptr;
  return __cryptsan_realloc(ptr, nmemb * size);
}

void *__cryptsan___memmove_chk(void *dest, const void *src, size_t len, size_t dstlen)
{
  CRYPTSAN_DEBUG("__cryptsan___memmove_chk with len %zu and dstlen %zu", len, dstlen);
  void *orig_dest = dest;
  if (dstlen < len)
    Die();
  if (check_autable(dest))
  {
    __cryptsan_aut_pointer((void *)((unsigned long)dest + len - 1));
    dest = __cryptsan_aut_pointer(dest);
  }
  if (check_autable(src))
  {
    __cryptsan_aut_pointer((void *)((unsigned long)src + len - 1));
    src = __cryptsan_aut_pointer(src);
  }
  memmove(dest, src, len);
  return orig_dest;
}

void *__cryptsan_memset(void *s, int c, size_t n)
{
  CRYPTSAN_DEBUG("__cryptsan_memset with len %zu", n);
  void *orig_s = s;
  if (check_autable(s))
  {
    __cryptsan_aut_pointer((void *)((unsigned long)s + n - 1));
    s = __cryptsan_aut_pointer(s);
  }
  memset(s, c, n);
  return orig_s;
}

void *__cryptsan___memset_chk(void *dest, int c, size_t len, size_t dstlen)
{
  CRYPTSAN_DEBUG("__cryptsan___memset_chk with len %zu", len);
  void *orig_dest = dest;
  if (dstlen < len)
    Die();
  if (check_autable(dest))
  {
    __cryptsan_aut_pointer((void *)((unsigned long)dest + len - 1));
    dest = __cryptsan_aut_pointer(dest);
  }
  memset(dest, c, len);
  return orig_dest;
}