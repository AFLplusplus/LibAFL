#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo "================================================="
echo "           Nyx build script"
echo "================================================="
echo


echo "[*] Making sure all Nyx is checked out"

git status 1>/dev/null 2>/dev/null

if [ ! -e ./QEMU-Nyx/.git ]; then
    rm -rf ./QEMU-Nyx
    git clone https://github.com/nyx-fuzz/QEMU-Nyx.git || exit 1
    pushd QEMU-Nyx
    git reset --hard e5e1c4c21ff9c4dc80e6409d4eab47146c6024cd
    popd
fi

if [ ! -e ./packer/.git ]; then
    rm -rf ./packer
    git clone https://github.com/nyx-fuzz/packer  || exit 1
    pushd packer
    git reset --hard bcf3e248b660764f48af54232a3388389a2dfc22
    popd
fi

git submodule init || exit 1
echo "[*] initializing QEMU-Nyx submodule"
cd QEMU-Nyx/ || return
git submodule update --init .
cd ..
echo "[*] initializing packer submodule"
git submodule update ./packer 2>/dev/null # ignore errors


test -e packer/.git || { echo "[-] packer not checked out, please install git or check your internet connection." ; exit 1 ; }
test -e QEMU-Nyx/.git || { echo "[-] QEMU-Nyx not checked out, please install git or check your internet connection." ; exit 1 ; }

echo "[*] Checking QEMU-Nyx ..."
if [ ! -f "QEMU-Nyx/x86_64-softmmu/qemu-system-x86_64" ]; then
    cd QEMU-Nyx/ || return
    # We need to copy our custom `Makefile.libxdc` after `git submodule update`, otherwise we get a git error.
    sed -i "s,git submodule update libxdc$,git submodule update libxdc \&\& cp ../Makefile.libxdc ./libxdc/Makefile || exit 1," compile_qemu_nyx.sh
    ./compile_qemu_nyx.sh lto || exit 1
    cd ..
fi

echo "[*] checking packer init.cpio.gz ..."
if [ ! -f "packer/linux_initramfs/init.cpio.gz" ]; then
    cd packer/linux_initramfs/ || return
    sh pack.sh || exit 1
    cd ../../
fi

echo "[+] All done for nyx_mode, enjoy!"

exit 0
