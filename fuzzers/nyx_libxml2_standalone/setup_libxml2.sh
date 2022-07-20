#!/bin/sh
cargo build --release
export CC=`pwd`/target/release/libafl_cc
export CXX=`pwd`/target/release/libafl_cxx
curl -C https://gitlab.gnome.org/GNOME/libxml2/-/archive/v2.9.14/libxml2-v2.9.14.tar.gz --output libxml2-v2.9.14.tar.gz
tar -xvf ./libxml2-v2.9.14.tar.gz  --transform s/libxml2-v2.9.14/libxml2/
cd ./libxml2/ || exit
./autogen.sh --enable-shared=no
make
cd - || exit
python3 "../../libafl_nyx/packer/packer/nyx_packer.py" \
    ./libxml2/xmllint \
    /tmp/nyx_libxml2 \
    afl \
    instrumentation \
    -args "/tmp/input" \
    -file "/tmp/input" \
    --fast_reload_mode \
    --purge

python3 ../../libafl_nyx/packer/packer/nyx_config_gen.py /tmp/nyx_libxml2/ Kernel
sudo modprobe -r kvm-intel # or kvm-amd for AMD 
sudo modprobe -r kvm
sudo modprobe kvm enable_vmware_backdoor=y
sudo modprobe kvm-intel
