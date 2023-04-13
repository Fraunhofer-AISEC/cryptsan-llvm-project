#!/usr/bin/env bash

# Build script for CryptSan with LLVM 12

# Variables are configured externaly! E.g. in a .env file for
# docker-compose

set -e

ROOT_DIR="$(pwd)"
BUILD_DIR="$(pwd)/$1"
INSTALL_DIR="$(pwd)/$2"
BUILD_COMPILER_RT_DIR="$(pwd)/$3"
BUILD_TYPE=Debug
SHARED_LIBS=YES
INSTALL_UTILS=ON
BUILD_CLANG=YES
BUILD_LLD=YES
BUILD_COMPILER_RT=YES
USE_GCC=NO
LINKER=lld
USE_CCACHE=NO
USE_DISTCC=NO

if [ ! -d "$BUILD_DIR" ]; then
    echo "Cannot find build directory \"$BUILD_DIR\"! Abort"
    exit 1
fi

if [ ! -d "$BUILD_COMPILER_RT_DIR" ]; then
    echo "Cannot find build directory \"$BUILD_COMPILER_RT_DIR\"! Abort"
    exit 1
fi

if [ ! -d "$INSTALL_DIR" ]; then
    echo "Cannot find install directory \"$INSTALL_DIR\"! Abort"
    exit 1
fi

cd $ROOT_DIR

if [[ $BUILD_CLANG == "YES" ]]; then
    if [ ! -d "clang" ]; then
	echo "Cannot find clang directory! Abort"
	exit 1
    fi
    [[ $ENABLED_PROJECTS == "" ]] && ENABLED_PROJECTS="clang" || ENABLED_PROJECTS+=";clang"
fi

if [[ $BUILD_LLD == "YES" ]]; then
    if [ ! -d "lld" ]; then
	echo "Cannot find lld directory! Abort"
	exit 1
    fi
    [[ $ENABLED_PROJECTS == "" ]] && ENABLED_PROJECTS="lld" || ENABLED_PROJECTS+=";lld"
fi

if [[ $USE_GCC == "YES" ]]; then
    C_COMPILER="/usr/bin/gcc"
    CXX_COMPILER="/usr/bin/g++"
else
    C_COMPILER="/usr/bin/clang"
    CXX_COMPILER="/usr/bin/clang++"
fi


if [[ $USE_CCACHE == "YES" ]]; then
    USE_CCACHE="ON"
else
    USE_CCACHE="OFF"
fi

if [[ $USE_DISTCC == "YES" ]]; then
    if [[ $USE_CCACHE == "ON" ]]; then
	export CCACHE_PREFIX=distcc
    else
	COMPILE_LAUNCHER="distcc"
    fi
fi


if [ ! -d "llvm" ]; then
    echo "Cannot find llvm directory! Abort"
    exit 1
fi

conf() {
    echo "Options that will be given to cmake:"
    echo -e "-G Ninja \n\
        -DCMAKE_INSTALL_PREFIX=\"$INSTALL_DIR\" \n\
        -DCMAKE_BUILD_TYPE=\"$BUILD_TYPE\" \n\
        -DLLVM_ENABLE_PROJECTS=\"$ENABLED_PROJECTS\" \n\
        -DCMAKE_C_COMPILER=\"$C_COMPILER\" \n\
        -DCMAKE_CXX_COMPILER=\"$CXX_COMPILER\" \n\
        -DLLVM_TARGETS_TO_BUILD=AArch64 \n\
        -DLLVM_USE_LINKER=\"$LINKER\" \n\
        -DLLVM_CCACHE_BUILD=\"$USE_CCACHE\" \n\
        -DBUILD_SHARED_LIBS=\"$SHARED_LIBS\" \n\
        -DLLVM_INSTALL_UTILS=\"$INSTALL_UTILS\" \n\
        -DCMAKE_C_COMPILER_LAUNCHER=\"$COMPILE_LAUNCHER\" \n\
        -DCMAKE_CXX_COMPILER_LAUNCHER=\"$COMPILE_LAUNCHER\""

    cmake -S "$(pwd)/llvm" -B "$BUILD_DIR" \
        -G Ninja \
        -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
        -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
        -DLLVM_ENABLE_PROJECTS="$ENABLED_PROJECTS" \
        -DCMAKE_C_COMPILER="$C_COMPILER" \
        -DCMAKE_CXX_COMPILER="$CXX_COMPILER" \
        -DLLVM_TARGETS_TO_BUILD="AArch64" \
        -DLLVM_USE_LINKER="$LINKER" \
        -DLLVM_CCACHE_BUILD="$USE_CCACHE" \
        -DBUILD_SHARED_LIBS="$SHARED_LIBS" \
        -DLLVM_INSTALL_UTILS="$INSTALL_UTILS" \
        -DCMAKE_C_COMPILER_LAUNCHER="$COMPILE_LAUNCHER" \
        -DCMAKE_CXX_COMPILER_LAUNCHER="$COMPILE_LAUNCHER"

}

compile() {
    if [[ $USE_DISTCC == "YES" ]]; then
        eval "$(distcc-pump --startup)"
        cmake --build "$BUILD_DIR" -j "$(distcc -j)" --target install
        distcc-pump --shutdown
    else
        if [[ ! -z ${BUILD_CORES+x} ]]; then
            cmake --build "$BUILD_DIR" -j "$BUILD_CORES" --target install
        else
            cmake --build "$BUILD_DIR" -j "$(nproc)" --target install
        fi

        if [[ $BUILD_COMPILER_RT == "YES" ]]; then
            echo "cmake -S "$(pwd)/compiler-rt" -B "$BUILD_COMPILER_RT_DIR" \
                -DLLVM_CONFIG_PATH="$BUILD_DIR/bin/llvm-config" \
                -DCMAKE_BUILD_TYPE=Debug                \
                -DBUILD_SHARED_LIBS=On                  \
                -DCOMPILER_RT_BUILD_BUILTINS=OFF        \
                -DCOMPILER_RT_BUILD_SANITIZERS=ON       \
                -DCOMPILER_RT_BUILD_XRAY=OFF            \
                -DCOMPILER_RT_BUILD_LIBFUZZER=OFF       \
                -DCOMPILER_RT_BUILD_PROFILE=OFF         \
                -DCMAKE_C_COMPILER="$BUILD_DIR/bin/clang"   \
                -DCMAKE_CXX_COMPILER="$BUILD_DIR/bin/clang++"   \
                -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld" \
                -DCMAKE_C_COMPILER_TARGET="aarch64-linux-gnu"   \
                -DCMAKE_CXX_COMPILER_TARGET="aarch64-linux-gnu" \
                -DCMAKE_ASM_COMPILER_TARGET="aarch64-linux-gnu" \
                -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON            \
                -DCMAKE_C_FLAGS="-O0 -fPIC --target=aarch64-linux-gnu -march=armv8.3-a+pauth"            \
                -DCMAKE_CXX_FLAGS="-O0 -fPIC --target=aarch64-linux-gnu -march=armv8.3-a+pauth""

            cmake -S "$(pwd)/compiler-rt" -B "$BUILD_COMPILER_RT_DIR" \
                -DLLVM_CONFIG_PATH="$BUILD_DIR/bin/llvm-config" \
                -DCMAKE_BUILD_TYPE=Debug                \
                -DBUILD_SHARED_LIBS=On                  \
                -DCOMPILER_RT_BUILD_BUILTINS=OFF        \
                -DCOMPILER_RT_BUILD_SANITIZERS=ON       \
                -DCOMPILER_RT_BUILD_XRAY=OFF            \
                -DCOMPILER_RT_BUILD_LIBFUZZER=OFF       \
                -DCOMPILER_RT_BUILD_PROFILE=OFF         \
                -DCMAKE_C_COMPILER="$BUILD_DIR/bin/clang"   \
                -DCMAKE_CXX_COMPILER="$BUILD_DIR/bin/clang++"   \
                -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld" \
                -DCMAKE_C_COMPILER_TARGET="aarch64-linux-gnu"   \
                -DCMAKE_CXX_COMPILER_TARGET="aarch64-linux-gnu" \
                -DCMAKE_ASM_COMPILER_TARGET="aarch64-linux-gnu" \
                -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON            \
                -DCMAKE_C_FLAGS="-O0 -fPIC --target=aarch64-linux-gnu -march=armv8.3-a+pauth"            \
                -DCMAKE_CXX_FLAGS="-O0 -fPIC --target=aarch64-linux-gnu -march=armv8.3-a+pauth"
            cd $BUILD_COMPILER_RT_DIR
            cmake --build "$BUILD_COMPILER_RT_DIR" -j "$(nproc)"
        fi
    fi
}

case $3 in
    configure)
        conf
        ;;
    build-only)
        compile
        ;;
    *)
        conf
        compile
        ;;
esac
