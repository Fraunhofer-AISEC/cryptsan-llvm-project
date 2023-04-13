//===-- cryptsan_wrappers.cc ---------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of CryptSan.
//
// CryptSan stdlib wrappers.
//===----------------------------------------------------------------------===//
#include "cryptsan/cryptsan.h"

#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include <stdio.h>
#include <string.h>

using namespace __cryptsan;

// memchr family

const void *__cryptsan_memchr(const void *s, int c, size_t n)
{
  const void *r = memchr(s, c, n);
  return r;
}

#ifdef _GNU_SOURCE
const void *__cryptsan_memrchr(const void *s, int c, size_t n)
{
  const void *r = memrchr(s, c, n);
  return r;
}
#endif

#ifdef _GNU_SOURCE
const void *__cryptsan_rawmemchr(const void *s, int c)
{
  const void *r = rawmemchr(s, c);
  return r;
}
#endif

// strchr family

const char *__cryptsan_strchr(const char *s, int c)
{
  const char *r = strchr(s, c);
  return r;
}

const char *__cryptsan_strrchr(const char *s, int c)
{
  const char *r = strrchr(s, c);
  return r;
}

#ifdef _GNU_SOURCE
const char *__cryptsan_strchrnul(const char *s, int c)
{
  const char *r = strchrnul(s, c);
  return r;
}
#endif

// strstr family

const char *__cryptsan_strstr(const char *haystack, const char *needle)
{
  const char *r = strstr(haystack, needle);
  return r;
}

#ifdef _GNU_SOURCE
const char *__cryptsan_strcasestr(const char *haystack, const char *needle)
{
  const char *r = strcasestr(haystack, needle);
  return r;
}
#endif

wchar_t *__cryptsan_wcscpy(wchar_t *dest, wchar_t *src)
{
  CRYPTSAN_DEBUG("__cryptsan_wcscpy");

  if (check_autable(src))
  {
    src = (wchar_t *)__cryptsan_aut_pointer(src);
  }
  size_t len = wcslen(src);
  if (check_autable(dest))
  {
    __cryptsan_aut_pointer(dest + len);
    dest = (wchar_t *)__cryptsan_aut_pointer(dest);
  }
  return wcscpy(dest, src);
}

char *__cryptsan_strcpy(char *d, char *s)
{
  CRYPTSAN_DEBUG("__cryptsan_strcpy %llx, %llx", (unsigned long)d, (unsigned long)s);
  char *tmp_d = d;
  size_t len = strlen((const char *)poms_strip_pac(s));
  s = (char *)__cryptsan_aut_pointer(s);

  d = (char *)__cryptsan_aut_pointer(d);
  __cryptsan_aut_pointer(tmp_d + len);
  strcpy(d, s);
  return tmp_d;
}

char *__cryptsan___strcpy_chk(char *d, char *s, size_t dstlen)
{
  CRYPTSAN_DEBUG("__cryptsan___strcpy_chk");
  if (check_autable(s))
  {
    s = (char *)__cryptsan_aut_pointer(s);
  }
  size_t len = strlen(s) + 1;
  CRYPTSAN_DEBUG("len = %zu", len);
  if (check_autable(d))
  {
    __cryptsan_aut_pointer(d + len);
    d = (char *)__cryptsan_aut_pointer(d);
  }

  return strcpy(d, s);
}

char *__cryptsan_strcat(char *d, char *s)
{
  CRYPTSAN_DEBUG("__cryptsan_strcat");
  if (check_autable(s))
  {
    s = (char *)__cryptsan_aut_pointer(s);
  }
  size_t s_len = strlen(s);
  CRYPTSAN_DEBUG("len = %zu", s_len);
  if (check_autable(d))
  {
    char *orig_d = d;
    d = (char *)__cryptsan_aut_pointer(d);
    size_t d_len = strlen(d);

    __cryptsan_aut_pointer(orig_d + s_len + d_len);
  }

  return strcat(d, s);
}

char *__cryptsan___strcat_chk(char *d, char *s, size_t n)
{
  CRYPTSAN_DEBUG("__cryptsan___strcat_chk");
  if (check_autable(s))
  {
    s = (char *)__cryptsan_aut_pointer(s);
  }
  size_t s_len = strlen(s);
  CRYPTSAN_DEBUG("len = %zu", s_len);
  if (check_autable(d))
  {
    char *orig_d = d;
    d = (char *)__cryptsan_aut_pointer(d);
    size_t d_len = strlen(d);

    __cryptsan_aut_pointer(orig_d + s_len + d_len);
  }

  return strcat(d, s);
}

char *__cryptsan_strncpy(char *d, char *s, unsigned long n)
{
  CRYPTSAN_DEBUG("__cryptsan_strncpy %llx %llx", d, s);
  if (check_autable(s))
  {
    __cryptsan_aut_pointer(s + n);
    s = (char *)__cryptsan_aut_pointer(s);
  }

  if (check_autable(d))
  {
    __cryptsan_aut_pointer(d + n);
    d = (char *)__cryptsan_aut_pointer(d);
  }
  return strncpy(d, s, n);
}

char *__cryptsan___strncpy_chk(char *d, char *s, unsigned long n, size_t dstlen)
{
  CRYPTSAN_DEBUG("__cryptsan___strncpy_chk");
  if (check_autable(s))
  {
    s = (char *)__cryptsan_aut_pointer(s);
  }

  if (check_autable(d))
  {
    if (n > 0)
    {
      __cryptsan_aut_pointer(d + n - 1);
    }
    d = (char *)__cryptsan_aut_pointer(d);
  }
  return strncpy(d, s, n);
}

char *__cryptsan_strncat(char *d, char *s, unsigned long n)
{
  CRYPTSAN_DEBUG("__cryptsan_strncat");
  if (check_autable(s))
  {
    s = (char *)__cryptsan_aut_pointer(s);
  }

  if (check_autable(d))
  {
    __cryptsan_aut_pointer(d + n - 1);
    d = (char *)__cryptsan_aut_pointer(d);
  }
  return strncat(d, s, n);
}

char *__cryptsan___strncat_chk(char *d, char *s, unsigned long n, size_t dstlen)
{
  CRYPTSAN_DEBUG("__cryptsan_strncat");
  if (check_autable(s))
  {
    s = (char *)__cryptsan_aut_pointer(s);
  }

  if (check_autable(d))
  {
    __cryptsan_aut_pointer(d + n - 1);
    d = (char *)__cryptsan_aut_pointer(d);
  }
  return strncat(d, s, n);
}

char *__cryptsan_strtok(char *str, const char *delim)
{
  CRYPTSAN_DEBUG("__cryptsan_strtok");

  const char *tmp_delim = check_autable(delim) ? (const char *)__cryptsan_aut_pointer(delim) : delim;

  if (check_autable(str))
  {
    uptr *mask = poms_get_mask(str);
    str = (char *)__cryptsan_aut_pointer(str);
    str = strtok(str, tmp_delim);
    str = (char *)poms_apply_mask(str, mask);
    return str;
  }
  else
  {
    str = strtok(str, tmp_delim);
    return str;
  }
}