//===-- cryptsan.cc ---------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of CryptSan.
//
// CryptSan initialization.
//===----------------------------------------------------------------------===//
#include "cryptsan/cryptsan.h"
#if defined(__APPLE__)
#else
#include <sys/prctl.h>
#endif
#include <errno.h>

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_procmaps.h"

bool PrintDebugOutput = true;

#if defined(__APPLE__)
void InitPrctl() {}
#else
void InitPrctl() {
#define PR_SET_TAGGED_ADDR_CTRL 55
#define PR_GET_TAGGED_ADDR_CTRL 56
#define PR_TAGGED_ADDR_ENABLE (1UL << 0)
  if (__asan::internal_prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0) == (uptr)-1 &&
      errno == EINVAL) {
        return;
  }
  if (__asan::internal_prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE, 0, 0, 0) ==
          (uptr)-1 ||
      !__asan::internal_prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0)) {
        return;
  }
}
#undef PR_SET_TAGGED_ADDR_CTRL
#undef PR_GET_TAGGED_ADDR_CTRL
#undef PR_TAGGED_ADDR_ENABLE
#endif

namespace __cryptsan
{

  // Indicators whether the CRYPTSAN runtime is fully initialized.
  bool CryptSanIsInitialized = false;
  static bool CryptSanPomsIsInitialized = false;

  // Size of the user space memory range.
  static uptr kMemSize;

  // Size and bounds of the per-object metadata store.
  static uptr kPomsSize;
  static uptr kPomsLowerBound;
  static uptr kPomsUpperBound;

  // Initializes the per-object (fist level) metadata store.
  static void poms_init()
  {
    if (CryptSanPomsIsInitialized)
      return;

    InitPrctl();

    // Define the entire memory range.
    kMemSize = GetMaxUserVirtualAddress() + 1;

    // Check that the memory range is greater than 4 bytes.
    CHECK_GE(kMemSize, 4);

    // FIXME: Ideally, when the memory range is not a power of two, we want to
    // round down to the next power of two and restrict it accordingly.
    // Check that the memory range is a power of two.
    CHECK(kMemSize && !(kMemSize & (kMemSize - 1)));

    // Calculate size, lower bound, and upper bound of the per-object metadata
    // store.
    kPomsSize = kMemSize / 2;
#ifdef __APPLE__ // Apple places stack on lower memory end
    kPomsLowerBound = kPomsSize;
    kPomsSize -= 0x10000000; // TODO_kh: Full Size shadow leads to mmap error
#else
    kPomsLowerBound = kPomsSize / 2;
#endif
    kPomsUpperBound = kPomsLowerBound + kPomsSize - 1;

    CRYPTSAN_DEBUG("GetMaxUserVirtualAddress = 0x%llx", (unsigned long)kMemSize);
    CRYPTSAN_DEBUG("kPomsSize = 0x%llx", (unsigned long)kPomsSize);
    CRYPTSAN_DEBUG("POMS Start = 0x%llx", (unsigned long)kPomsLowerBound);
    CRYPTSAN_DEBUG("POMS End = 0x%llx", (unsigned long)kPomsUpperBound);

    // Don't count the per-object metadata store size against the mmap limit.
    DecreaseTotalMmap(kPomsSize);

    // Allocate the per-object metadata store.
    if (!MmapFixedNoReserve(kPomsLowerBound, kPomsSize))
    {
      DumpProcessMap();
      CHECK("unable to mmap" && 0);
    }

    CryptSanPomsIsInitialized = true;
  }

  // Add per-object metadata for a new object.
  void poms_add(const uptr *start, const u32 id, const uptr size)
  {
    CRYPTSAN_DEBUG("Add id: %x, full ids: %d", id, size / 4);
    u32 *end = (u32 *)start + (size / 4);
    unsigned int rem = size % 4;

    CRYPTSAN_DEBUG("PO Add: Start=0x%llx", (unsigned long)start);
    CRYPTSAN_DEBUG("PO Add: End=  0x%llx", (unsigned long)end);
    u32 *MetadataPtr = (u32 *)poms_ptr(start);
    u32 *MetadataEnd = (u32 *)poms_ptr(end);

    CRYPTSAN_DEBUG("PO Add: MPtr= 0x%llx", (unsigned long)MetadataPtr);
    CRYPTSAN_DEBUG("PO Add: MEnd= 0x%llx", (unsigned long)MetadataEnd);

    while (MetadataPtr < MetadataEnd)
    {
      *MetadataPtr = id;
      MetadataPtr++;
    }
    if (rem)
    {
      *MetadataPtr = id;
      MetadataPtr++;
    }
  }

  /* used for propagating pointer metadata for memintrinsics, ie memcpy and memmove */
  void poms_copy_ptr_md_region(const uptr *dest, const uptr *src, uptr len)
  {
    u32 *MetadataSrc = (u32 *)poms_ptr(src);
    u32 *MetadataDest = (u32 *)poms_ptr(dest);
    CRYPTSAN_DEBUG("PO Copy Metadata Src= 0x%llx; Dest=0x%llx; size=%d", src, dest, len);
    CRYPTSAN_DEBUG("PO Copy Metadata MDSrc= 0x%llx; MDDest=0x%llx", MetadataSrc, MetadataDest);

    for (uptr i = 0; i < poms_align_size(len) / sizeof(uptr); ++i)
    {
      // Use ID from previous memory
      MetadataDest[i] = MetadataSrc[0];
      CRYPTSAN_DEBUG("i=%d, MDSource=0x%llx, MDDest=0x%llx", i, MetadataSrc[i], MetadataDest[i]);
    }
  }

  void poms_remove(uptr *ptr, unsigned long value)
  {
    u32 *MetadataPtr = (u32 *)poms_ptr(ptr);
    u32 id = *MetadataPtr;

    CRYPTSAN_DEBUG("PO Remove: mptr= 0x%llx", (unsigned long)MetadataPtr);
    if (id != 0)
    {
      while (*MetadataPtr == id)
      {
        *MetadataPtr++ = value;
      }
    }
  }

  void poms_remove(uptr *start, uptr *end, unsigned long value)
  {

    CRYPTSAN_DEBUG("PO Remove: start=0x%llx", (unsigned long)start);
    CRYPTSAN_DEBUG("PO Remove: end=  0x%llx", (unsigned long)end);
    u32 *MetadataPtr = (u32 *)poms_ptr(start);
    u32 *MetadataEnd = (u32 *)poms_ptr(end);
    CRYPTSAN_DEBUG("PO Remove: mptr= 0x%llx", (unsigned long)MetadataPtr);
    CRYPTSAN_DEBUG("PO Remove: mend= 0x%llx", (unsigned long)MetadataEnd);
    while (MetadataPtr < MetadataEnd)
    {
      *MetadataPtr++ = STATUS_FREED;
    }
  }

} // namespace __cryptsan

using namespace __cryptsan;

void __cryptsan_init_rt()
{
  if (CryptSanIsInitialized)
    return;

  SetCommonFlagsDefaults();

  CRYPTSAN_DEBUG("CRYPTSAN runtime initialization");

  // Sanity check: Alginment must be a divisor of the page size.
  CHECK_EQ(GetMmapGranularity() % POMS_ALIGNMENT, 0);

  // Initialize first and second level metadata stores.
  poms_init();
  CRYPTSAN_DEBUG("POMS initialized");
  CryptSanIsInitialized = true;
}

void __cryptsan_init_global(uint32_t *glob_ptr, uint32_t **paced_global_ptr, uint32_t glob_size)
{
  CRYPTSAN_DEBUG("Init global %llx of size %llx and write tagged_ptr to %llx", (unsigned long)glob_ptr, glob_size, (unsigned long)paced_global_ptr);

  u32 id = __cryptsan_get_next_id();
  poms_add((uptr *)glob_ptr, id, glob_size);
  void *id_ptr = (void *)(u64)id;
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
      : "+r"(id_ptr)
      : [input_ptr] "r"(id_ptr));
#endif

  uptr *mask = poms_get_mask(id_ptr);
  uint32_t *tagged_global_ptr = (uint32_t *)poms_apply_mask(glob_ptr, mask);
  *paced_global_ptr = tagged_global_ptr;
  CRYPTSAN_DEBUG("paced_global_ptr %llx", (unsigned long)tagged_global_ptr);
}

void __cryptsan_init_global_with_id(uint32_t valueid, uint32_t *glob_ptr, uint32_t **paced_global_ptr, uint32_t glob_size)
{
  CRYPTSAN_DEBUG("Init global %llx at %llx of size %llx and write tagged_ptr to %llx", valueid, (unsigned long)glob_ptr, glob_size, (unsigned long)paced_global_ptr);
  u32 id;
  u32 prev_id = *poms_ptr(glob_ptr);
  if (prev_id)
  {
    id = prev_id;
  }
  else
  {
    id = __cryptsan_get_next_id();
    poms_add((uptr *)glob_ptr, id, glob_size);
  }
  void *id_ptr = (void *)(u64)id;
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
  uint32_t *tagged_global_ptr = (uint32_t *)poms_apply_mask(glob_ptr, mask);
  *paced_global_ptr = tagged_global_ptr;
}

void *__cryptsan_init_stack_variable(uint32_t *stack_ptr, uint64_t size)
{
  CRYPTSAN_DEBUG("__cryptsan_init_stack_variable %llx, size %llx", (unsigned long)stack_ptr, size);
  uint32_t *old_stack_ptr = stack_ptr;
  do
  {
    u32 id = __cryptsan_get_next_id();
    __cryptsan::poms_add((uptr *)stack_ptr, id, size);
    void *id_ptr = (void *)(u64)id;
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
        : "+r"(id_ptr)
        : [input_ptr] "r"(id_ptr));
#endif

    uptr *mask = poms_get_mask(id_ptr);
    stack_ptr = (uint32_t *)poms_apply_mask(stack_ptr, mask);
  } while (stack_ptr == old_stack_ptr);
  CRYPTSAN_DEBUG("return %llx", (unsigned long)stack_ptr);

  return stack_ptr;
}

void __cryptsan_init_main_args(int *argc_ptr, char ***argv_ptr)
{
  int argc = *argc_ptr;
  char **argv = *argv_ptr;
  u32 id = 0;
  for (int i = 0; i < argc; i++)
  {
    u32 argv_len = internal_strlen(argv[i]);
    poms_add((uptr *)argv[i], id, argv_len);
    void *id_ptr = (void *)(u64)id;
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
    char *tagged_argv = (char *)poms_apply_mask(argv[i], mask);
    argv[i] = tagged_argv;
  }

  u32 argv_len = argc * sizeof(argv[0]);
  poms_add((uptr *)argv, id, argv_len);
  void *id_ptr = (void *)(u64)id;
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
  CRYPTSAN_DEBUG("PAC ptr: 0x%llx", (unsigned long)id_ptr);

  uptr *mask = poms_get_mask(id_ptr);
  char **tagged_argv = (char **)poms_apply_mask(argv, mask);
  *argv_ptr = tagged_argv;
}
