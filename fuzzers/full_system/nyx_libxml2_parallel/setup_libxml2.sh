#!/bin/bash
# cargo build --release
# PWD=$(pwd)
# export CC="$PWD/target/release/libafl_cc"
# export CXX="$PWD/target/release/libafl_cxx"

# Check if afl-clang-fast exists in PATH
if ! command -v afl-clang-fast &> /dev/null
then
    echo "afl-clang-fast not found. Cloning and compiling AFLplusplus..."
    git clone https://github.com/AFLplusplus/AFLplusplus.git
    pushd AFLplusplus
    make
    popd
    export CC="$(pwd)/AFLplusplus/afl-clang-fast"
    export CXX="$(pwd)/AFLplusplus/afl-clang-fast++"
else
    echo "afl-clang-fast already exists in PATH."
    export CC="afl-clang-fast"
    export CXX="afl-clang-fast++"
fi

curl -C - https://gitlab.gnome.org/GNOME/libxml2/-/archive/v2.9.14/libxml2-v2.9.14.tar.gz --output libxml2-v2.9.14.tar.gz
tar -xf ./libxml2-v2.9.14.tar.gz  --transform s/libxml2-v2.9.14/libxml2/ || exit
cd ./libxml2/ || exit
./autogen.sh --enable-shared=no || exit
make -j || exit
cd - || exit
python3 "../../../libafl_nyx/packer/packer/nyx_packer.py" \
    ./libxml2/xmllint \
    /tmp/nyx_libxml2 \
    afl \
    instrumentation \
    -args "/tmp/input" \
    -file "/tmp/input" \
    --fast_reload_mode \
    --purge || exit

python3 ../../../libafl_nyx/packer/packer/nyx_config_gen.py /tmp/nyx_libxml2/ Kernel || exit
