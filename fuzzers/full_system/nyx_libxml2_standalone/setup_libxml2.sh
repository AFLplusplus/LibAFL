#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
# cargo build --release
# PWD=$(pwd)
# export CC="$PWD/target/release/libafl_cc"
# export CXX="$PWD/target/release/libafl_cxx"

# Set LLVM_CONFIG if not set
if [ -z "$LLVM_CONFIG" ]; then
    # Build the find_llvm_config utility
    pushd "$SCRIPT_DIR/../../../utils/find_llvm_config"
    cargo build --release
    popd
    # It is in workspace target
    if [ -f "$SCRIPT_DIR/../../../target/release/find_llvm_config" ]; then
        LLVM_CONFIG=$("$SCRIPT_DIR/../../../target/release/find_llvm_config")
    elif [ -f "$SCRIPT_DIR/../../../utils/find_llvm_config/target/release/find_llvm_config" ]; then
        LLVM_CONFIG=$("$SCRIPT_DIR/../../../utils/find_llvm_config/target/release/find_llvm_config")
    else
        echo "Could not find find_llvm_config binary"
        exit 1
    fi
    export LLVM_CONFIG
fi

# Ensure QEMU-Nyx is available
QEMU_NYX_BIN="$SCRIPT_DIR/../../../target/debug/QEMU-Nyx/x86_64-softmmu/qemu-system-x86_64"
if [ ! -f "$QEMU_NYX_BIN" ]; then
    echo "QEMU-Nyx not found at $QEMU_NYX_BIN. Building libafl_nyx..."
    pushd "$SCRIPT_DIR/../../.." > /dev/null
    cargo build -p libafl_nyx || echo "Failed to build libafl_nyx, continuing anyway..."
    popd > /dev/null
fi

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

if [ -f "$QEMU_NYX_BIN" ]; then
    echo "Found QEMU-Nyx at $QEMU_NYX_BIN"
    # Create nyx.ini with correct QEMU path
    # We only need to set QEMU-PT_PATH, others will default to relative paths which are correct
    echo "[Packer]" > "$PACKER_DIR/nyx.ini"
    echo "QEMU-PT_PATH=$QEMU_NYX_BIN" >> "$PACKER_DIR/nyx.ini"
else
    echo "WARNING: QEMU-Nyx still not found. nyx_config_gen.py might fail."
fi

if [ -z "$AFL_CC" ]; then
    export AFL_CC="$($LLVM_CONFIG --bindir)/clang"
    export AFL_CXX="$($LLVM_CONFIG --bindir)/clang++"
fi

# Use libafl_cc
# We build it from the current crate (nyx_libxml2_parallel) which has src/bin/libafl_cc.rs
echo "Building libafl_cc..."
cargo build --bin libafl_cc

LIBAFL_CC="$SCRIPT_DIR/target/debug/libafl_cc"
LIBAFL_CXX="$SCRIPT_DIR/target/debug/libafl_cxx"

# Create symlink for C++ if missing
if [ ! -f "$LIBAFL_CXX" ]; then
    ln -s "$LIBAFL_CC" "$LIBAFL_CXX"
fi

export CC="$LIBAFL_CC"
export CXX="$LIBAFL_CXX"

echo "DEBUG: CC: $CC"
$CC --version

curl -L https://gitlab.gnome.org/GNOME/libxml2/-/archive/v2.9.14/libxml2-v2.9.14.tar.gz --output libxml2-v2.9.14.tar.gz
tar -xf ./libxml2-v2.9.14.tar.gz  --transform s/libxml2-v2.9.14/libxml2/ || exit
cd ./libxml2/ || exit
./autogen.sh --enable-shared=no --without-python || exit
make -j || exit
cd - || exit




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
