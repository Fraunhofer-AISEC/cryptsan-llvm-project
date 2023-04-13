include_directories(..)

# Runtime library sources and build flags.
set(CRYPTSAN_RTL_SOURCES
  cryptsan.cc
  pacinst.cc
  cryptsan_exceptions.cc
  cryptsan_stacktrace.cc
  cryptsan_malloc.cc
  cryptsan_wrappers.cc
  )

set(CRYPTSAN_RTL_HEADERS
  cryptsan.h
  cryptsan_interface_internal.h)

if(APPLE)
  set(CRYPTSAN_RTL_CFLAGS ${SANITIZER_COMMON_CFLAGS} -fno-strict-aliasing)
  set(CRYPTSAN_RTL_LTO_CFLAGS ${SANITIZER_COMMON_CFLAGS} -fno-strict-aliasing -flto)
else()
  set(CRYPTSAN_RTL_CFLAGS ${SANITIZER_COMMON_CFLAGS} -fno-strict-aliasing --target=aarch64-linux-gnu -march=armv8.3-a+pauth)
  set(CRYPTSAN_RTL_LTO_CFLAGS ${SANITIZER_COMMON_CFLAGS} -fno-strict-aliasing -flto --target=aarch64-linux-gnu -march=armv8.3-a+pauth)
endif()
append_rtti_flag(OFF CRYPTSAN_RTL_CFLAGS)

set(CRYPTSAN_RTL_DYNAMIC_CFLAGS ${CRYPTSAN_RTL_CFLAGS})
append_list_if(COMPILER_RT_HAS_FTLS_MODEL_INITIAL_EXEC
    -ftls-model=initial-exec CRYPTSAN_RTL_DYNAMIC_CFLAGS)

# Static runtime library.
add_compiler_rt_component(cryptsan)

add_compiler_rt_object_libraries(RTCryptSan_dynamic
  OS ${SANITIZER_COMMON_SUPPORTED_OS}
  ARCHS ${CRYPTSAN_SUPPORTED_ARCH}
  SOURCES ${CRYPTSAN_RTL_SOURCES}
  ADDITIONAL_HEADERS ${CRYPTSAN_RTL_HEADERS}
  CFLAGS ${CRYPTSAN_RTL_DYNAMIC_CFLAGS})
message(STATUS "CryptSanDynamic 
  OS ${SANITIZER_COMMON_SUPPORTED_OS}
  ARCHS ${CRYPTSAN_SUPPORTED_ARCH}
  SOURCES ${CRYPTSAN_RTL_SOURCES}
  ADDITIONAL_HEADERS ${CRYPTSAN_RTL_HEADERS}
  CFLAGS ${CRYPTSAN_RTL_DYNAMIC_CFLAGS}")
if(NOT APPLE)
  add_compiler_rt_object_libraries(RTCryptSan
    ARCHS ${CRYPTSAN_SUPPORTED_ARCH}
    SOURCES ${CRYPTSAN_RTL_SOURCES}
    ADDITIONAL_HEADERS ${CRYPTSAN_RTL_HEADERS}
    CFLAGS ${CRYPTSAN_RTL_CFLAGS})
endif()
if(APPLE)
  add_weak_symbols("sanitizer_common" WEAK_SYMBOL_LINK_FLAGS)
  set(CRYPTSAN_LINK_LIBS ${SANITIZER_COMMON_LINK_LIBS})
  add_compiler_rt_runtime(clang_rt.cryptsan
    SHARED
    OS ${SANITIZER_COMMON_SUPPORTED_OS}
    ARCHS ${CRYPTSAN_SUPPORTED_ARCH}
    OBJECT_LIBS RTCryptSan_dynamic
                RTInterception
                RTSanitizerCommon
                RTSanitizerCommonLibc
                RTSanitizerCommonCoverage
                RTSanitizerCommonSymbolizer
    CFLAGS ${CRYPTSAN_RTL_DYNAMIC_CFLAGS}
    LINK_FLAGS ${SANITIZER_COMMON_LINK_FLAGS} ${WEAK_SYMBOL_LINK_FLAGS}
    LINK_LIBS ${CRYPTSAN_LINK_LIBS}
    PARENT_TARGET cryptsan)
else()
  foreach(arch ${CRYPTSAN_SUPPORTED_ARCH})
      add_compiler_rt_runtime(clang_rt.cryptsan
        STATIC
        ARCHS ${arch}
        OBJECT_LIBS RTCryptSan
                    RTInterception
                    RTSanitizerCommon
                    RTSanitizerCommonLibc
                    RTSanitizerCommonCoverage
                    RTSanitizerCommonSymbolizer
        CFLAGS ${CRYPTSAN_RTL_CFLAGS}
        PARENT_TARGET cryptsan)
      add_sanitizer_rt_symbols(clang_rt.cryptsan
        ARCHS ${arch}
        #EXTRA cryptsan.syms.extra
        )
      add_dependencies(cryptsan
        clang_rt.cryptsan-${arch}-symbols)
        add_compiler_rt_runtime(clang_rt.cryptsan_lto
        STATIC
        ARCHS ${arch}
        OBJECT_LIBS RTCryptSan
                    RTInterception
                    RTSanitizerCommon
                    RTSanitizerCommonLibc
                    RTSanitizerCommonCoverage
                    RTSanitizerCommonSymbolizer
        CFLAGS ${CRYPTSAN_RTL_LTO_CFLAGS}
        PARENT_TARGET cryptsan)
      add_sanitizer_rt_symbols(clang_rt.cryptsan_lto
        ARCHS ${arch}
        #EXTRA cryptsan.syms.extra
        )
      add_dependencies(cryptsan
        clang_rt.cryptsan_lto-${arch}-symbols)
  endforeach()
endif()