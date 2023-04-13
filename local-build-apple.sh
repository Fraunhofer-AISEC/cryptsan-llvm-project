BUILD_FILE="llvm/utils/docker/CryptSan/build_apple.sh"
BUILD_DIR="build-dir"
INSTALL_DIR="install-dir"
BUILD_COMPILER_RT_DIR="build-compiler-rt-dir"
EXAMPLE_DIR="example_app"

mkdir -p "$BUILD_DIR"
mkdir -p "$BUILD_COMPILER_RT_DIR"
mkdir -p "$INSTALL_DIR"
./$BUILD_FILE "$BUILD_DIR" "$INSTALL_DIR" "$BUILD_COMPILER_RT_DIR" build
