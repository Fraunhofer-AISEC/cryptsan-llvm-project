//===-- cryptsan_interface_internal.h ---------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of CryptSan.
//
// CryptSan Interface Internal.
//===----------------------------------------------------------------------===//
#ifndef CRYPTSAN_INTERFACE_INTERNAL_H
#define CRYPTSAN_INTERFACE_INTERNAL_H

#include "sanitizer_common/sanitizer_internal_defs.h"
#include <stdlib.h>
#include <sys/mman.h>
#include <stdint.h>
#include <wchar.h>



#define __WEAK__ __attribute__((__weak__))
#define __WEAK_INLINE __attribute__((__weak__, __always_inline__))

extern "C"
{

    using __sanitizer::uptr;

    // Callbacks

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void *__cryptsan_force_aut(void *ptr);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void __cryptsan_init_rt();

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void *__cryptsan_init_stack_variable(uint32_t *, uint64_t);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void __cryptsan_clear_stack_variable(uptr *);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void __cryptsan_par_autdza(void *ptr);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void __cryptsan_init_global(uint32_t *, uint32_t **, uint32_t);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void __cryptsan_init_global_with_id(uint32_t, uint32_t *, uint32_t **, uint32_t);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void __cryptsan_debug(uint32_t, uint8_t *unsafe_gv, uint8_t **offset);


    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void __cryptsan_init_main_args(int *argc_ptr, char ***argv_ptr);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void *__cryptsan_rt_malloc(size_t size);
    
    SANITIZER_INTERFACE_ATTRIBUTE
    uint32_t __cryptsan_get_next_id(void);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void *__cryptsan_memcpy(void *, const void *, size_t);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void *__cryptsan___memcpy_chk(void *, const void *, size_t, size_t);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void *__cryptsan_malloc(size_t size);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void *__cryptsan_aut_at_offset(const void *ptr, int offset);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void *__cryptsan_aut_pointer(const void *ptr);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void *__cryptsan_reapply_mask(const void *ptr);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    bool __cryptsan_check_autable(void *ptr);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void __cryptsan_free(void *ptr);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void *__cryptsan_calloc(uptr nmemb, size_t size);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void *__cryptsan_realloc(void *old_ptr, size_t new_size);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void *__cryptsan_reallocarray(void *ptr, size_t nmemb, size_t size);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    const void *__cryptsan_memchr(const void *s, int c, size_t n);

#ifdef _GNU_SOURCE
    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    const void *__cryptsan_memrchr(const void *s, int c, size_t n);
#endif

#ifdef _GNU_SOURCE
    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    const void *__cryptsan_rawmemchr(const void *s, int c);
#endif

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void *__cryptsan_memmove(void *dest, const void *src, size_t n);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void *__cryptsan_llvm_memmove(void *dest, void *src, size_t n, int8_t i);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void *__cryptsan___memmove_chk(void *dest, const void *src, size_t len, size_t dstlen);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void *__cryptsan_memset(void *s, int c, size_t n);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void *__cryptsan___memset_chk(void *dest, int c, size_t len, size_t dstlen);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    void *__cryptsan_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
    
    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    wchar_t *__cryptsan_wcscpy(wchar_t *, wchar_t *);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    char *__cryptsan_strcpy(char *, char *);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    char *__cryptsan___strcpy_chk(char *, char *, size_t dstlen);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    char *__cryptsan_strtok(char *str, const char *delim);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    char *__cryptsan_strcat(char *destination, char *source);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    char *__cryptsan___strcat_chk(char *destination, char *source, size_t n);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    char *__cryptsan_strncpy(char *, char *, unsigned long);


    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    int __cryptsan_snprintf(char *str, size_t n, char *__format, ...);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    char *__cryptsan___strncpy_chk(char *d, char *s, unsigned long n, size_t dstlen);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    char *__cryptsan_strncat(char *, char *, unsigned long);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    char *__cryptsan___strncat_chk(char *d, char *s, unsigned long n, size_t dstlen);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    const char *__cryptsan_strchr(const char *s, int c);

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    const char *__cryptsan_strrchr(const char *s, int c);

#ifdef _GNU_SOURCE
    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    const char *__cryptsan_strchrnul(const char *s, int c);
#endif

    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    const char *__cryptsan_strstr(const char *haystack, const char *needle);

#ifdef _GNU_SOURCE
    SANITIZER_INTERFACE_ATTRIBUTE
    __WEAK_INLINE
    const char *__cryptsan_strcasestr(const char *haystack, const char *needle);
#endif

} // extern "C"

#endif // CRYPTSAN_INTERFACE_INTERNAL_H
