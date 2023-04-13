//===-- cryptsan.h ---------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of CryptSan.
//
// CryptSan Defines and Declarations.
//===----------------------------------------------------------------------===//
#ifndef CRYPTSAN_H
#define CRYPTSAN_H

#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "cryptsan/cryptsan_interface_internal.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_tls_get_addr.h"

#define FAST_ERROR_DETECTION // segfaults take a long time to resolve, so make it quicker by crashing in check_autable
// #define SIM
#define POMS_ALIGNMENT       4
#define STATUS_FREED         0x0
#define STATUS_UNINITIALIZED 0x0
//#define PAC_USE_QEMU
#if defined(__APPLE__)
//  Apple:  GetMaxUserVirtualAddress = 0x800000000000 --> 0x200000000000
  #define POMS_OFFSET     0x400000000000
  #define PAC_STRIP_MASK  0x000007FFFFFFFFFFULL
  #define PAC_GET_MASK    0xFFFFF80000000000ULL
  #define ERROR_MASK      0x20000000000000ULL
#else 
#if(PAC_USE_QEMU)
//  Qemu:   GetMaxUserVirtualAddress 	= 0x2000000000 --> 0x800000000
  #define POMS_OFFSET     0x800000000
  #define PAC_STRIP_MASK  0x0000FFFFFFFFFFFFULL
  #define PAC_GET_MASK    0xFFFFF80000000000ULL
  #define ERROR_MASK      0x20000000000000ULL
#else
// Linux:  GetMaxUserVirtualAddress = 0x1000000000000 --> 
  #define POMS_OFFSET     0x400000000000
  #define PAC_STRIP_MASK  0x0000FFFFFFFFFFFFULL
  #define PAC_GET_MASK    0xFFFF000000000000ULL
  #define ERROR_MASK      0x20000000000000ULL
#endif
#endif


#define abort(...) { Printf(__VA_ARGS__); Die(); }
#define DEBUG 0
#define WARN 0

#if DEBUG
# define CRYPTSAN_DEBUG(fmt, ...) do { \
    Printf("(CRYPTSAN) " fmt "\n", ##__VA_ARGS__); \
  } while(0)
#else
# define CRYPTSAN_DEBUG(fmt, ...) do {} while(0)
#endif

#if defined(WARN)
# define CRYPTSAN_WARN(fmt, ...) do { \
    Printf("(CRYPTSAN WARN) " fmt "\n", ##__VA_ARGS__); \
  } while(0)
#else
# define CRYPTSAN_WARN(fmt, ...) do {} while(0)
#endif

#define CRYPTSAN_ERROR(fmt, ...) do { \
  Printf("(CRYPTSAN ERROR) " fmt "\n", ##__VA_ARGS__); \
} while(0)


static inline bool detect_error(const volatile void *ptr) {
  return (((uptr)ptr & ERROR_MASK) == ERROR_MASK);
}

static inline uptr* poms_ptr(const void *ptr) {
	return (uptr *)((uptr) ptr ^ (uptr) POMS_OFFSET); 
}

static inline uptr* align_to_word(const void *ptr) {
	return (uptr *)((uptr) ptr & -0x4ULL); 
}

static inline uptr* align_to_double_word(const void *ptr) {
	return (uptr *)((uptr) ptr & -0x8ULL); 
}

static inline uptr* poms_strip_pac(const void *ptr) {
	return (uptr *)((uptr) ptr & (uptr) PAC_STRIP_MASK);  
}

static inline uptr* poms_get_mask(const void *ptr) {
	return (uptr *)((uptr) ptr & PAC_GET_MASK);  
}

static inline uptr* poms_apply_mask(const void *ptr, const void *mask) {
	return (uptr *)((uptr) ptr | (uptr) mask);  
}


static inline bool check_autable(const void *ptr)
{
  uptr *tag = poms_get_mask(ptr);
  uptr *stripped = poms_strip_pac(ptr);
  stripped = align_to_word(stripped); // align to 4 Byte, same as id
  unsigned int id = *poms_ptr(stripped); // get pointer to meta data
  #ifdef FAST_ERROR_DETECTION
  if ((uptr)tag && !id) {
    __asan::Printf("CryptSan: detected tagged pointer without id, preemptive crash\n");
    __asan::Die();
  }
  #endif
  return id;
}

static inline uptr* combine(const void *ptr, const void *tagged_ptr) {
  uptr shadow_ptr = (uptr)ptr & PAC_STRIP_MASK;
  uptr tag = (uptr)tagged_ptr & PAC_GET_MASK;
  shadow_ptr |= tag;
  return (uptr *)(shadow_ptr);
}

static inline uint32_t get_base_ptr(const void *ptr, uptr id) {
  uint32_t * shadow_ptr = (uint32_t *)poms_ptr(ptr);
  uint32_t offset = 0;
  while (*(--shadow_ptr) == id) {
    offset++;
  }
  return offset;
}


namespace __cryptsan {

extern bool CryptSanIsInitialized;

inline uptr poms_align_size(uptr size) {
  if (size % POMS_ALIGNMENT == 0)
    return size;
  return size + (POMS_ALIGNMENT - (size % POMS_ALIGNMENT));
}

void poms_add(const uptr *start, const u32 id, const uptr size);
void poms_copy_ptr_md_region(const uptr *dest, const uptr *src, uptr len);
uptr poms_rearrange(uptr *start, uptr *end);
void poms_remove(uptr *ptr, unsigned long value);
void poms_remove(uptr *start, uptr *end, unsigned long value);

void initialize_interceptors();

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void print_stack_trace();

} // namespace __cryptsan

#endif  // CRYPTSAN_H
