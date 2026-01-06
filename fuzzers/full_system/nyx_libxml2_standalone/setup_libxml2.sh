#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
# cargo build --release
# PWD=$(pwd)
# export CC="$PWD/target/release/libafl_cc"
# export CXX="$PWD/target/release/libafl_cxx"

# Set LLVM_CONFIG if not set
if [ -z "$LLVM_CONFIG" ]; then
    # Build the get_llvm_config utility
    pushd "$SCRIPT_DIR/../../../utils/get_llvm_config"
    cargo build --release
    popd
    LLVM_CONFIG=$("$SCRIPT_DIR/../../../utils/get_llvm_config/target/release/get_llvm_config")
    export LLVM_CONFIG
fi

if [ -z "$AFL_CC" ]; then
    export AFL_CC="$($LLVM_CONFIG --bindir)/clang"
    export AFL_CXX="$($LLVM_CONFIG --bindir)/clang++"
fi

# Force local AFL++ build to avoid broken system binary
echo "Building local AFL++..."
export LLVM_CONFIG=llvm-config-18
if [ ! -d "AFLplusplus" ]; then
    git clone https://github.com/AFLplusplus/AFLplusplus.git
fi
pushd AFLplusplus
make clean
make
popd

export CC="$SCRIPT_DIR/AFLplusplus/afl-clang-fast"
export CXX="$SCRIPT_DIR/AFLplusplus/afl-clang-fast++"

echo "DEBUG: CC: $CC"
$CC --version

curl -L https://gitlab.gnome.org/GNOME/libxml2/-/archive/v2.9.14/libxml2-v2.9.14.tar.gz --output libxml2-v2.9.14.tar.gz
tar -xf ./libxml2-v2.9.14.tar.gz  --transform s/libxml2-v2.9.14/libxml2/ || exit
cd ./libxml2/ || exit
./autogen.sh --enable-shared=no --without-python || exit
make -j || exit
cd - || exit
PACKER_DIR="$SCRIPT_DIR/../../../libafl_nyx/packer/packer"
if [ ! -d "$PACKER_DIR" ]; then
    PACKER_DIR="$SCRIPT_DIR/target/debug/packer/packer"
fi

if [ ! -f "$PACKER_DIR/nyx_packer.py" ]; then
    echo "nyx_packer.py not found in $PACKER_DIR or source."
    echo "Cloning nyx-fuzz/packer to use packer..."
    # Clone into a temporary directory or local directory
    if [ ! -d "packer" ]; then
        git clone https://github.com/nyx-fuzz/packer
    fi
    PACKER_DIR="$(pwd)/packer/packer"
fi

echo "PACKER_DIR: $PACKER_DIR"

if [ ! -f "$PACKER_DIR/nyx_packer.py" ]; then
    echo "ERROR: nyx_packer.py still not found at $PACKER_DIR/nyx_packer.py"
    exit 1
fi

python3 "$PACKER_DIR/nyx_packer.py" \
    ./libxml2/xmllint \
    /tmp/nyx_libxml2 \
    afl \
    instrumentation \
    -args "/tmp/input" \
    -file "/tmp/input" \
    --fast_reload_mode \
    --purge || exit

# Config gen is also in packer dir
python3 "$PACKER_DIR/nyx_config_gen.py" /tmp/nyx_libxml2/ Kernel || exit
