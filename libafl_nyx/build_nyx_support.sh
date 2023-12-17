#!/bin/bash
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
    git reset --hard 80f22f77d6aab14e62bf11c80db4e210bbca5fb5
    popd
fi

if [ ! -e ./packer/.git ]; then
    rm -rf ./packer
    git clone https://github.com/syheliel/packer.git || exit 1
    pushd packer
    git reset --hard 86b159bafc0b2ba8feeaa8761a45b6201d34084f
    popd
fi

git submodule init || exit 1
echo "[*] initializing QEMU-Nyx submodule"
git submodule update ./QEMU-Nyx 2>/dev/null # ignore errors
echo "[*] initializing packer submodule"
git submodule update ./packer 2>/dev/null # ignore errors


test -e packer/.git || { echo "[-] packer not checked out, please install git or check your internet connection." ; exit 1 ; }
test -e QEMU-Nyx/.git || { echo "[-] QEMU-Nyx not checked out, please install git or check your internet connection." ; exit 1 ; }

echo "[*] checking packer init.cpio.gz ..."
if [ ! -f "packer/linux_initramfs/init.cpio.gz" ]; then
    cd packer/linux_initramfs/ || return
    sh pack.sh || exit 1
    cd ../../
fi


echo "[*] Checking QEMU-Nyx ..."
if [ ! -f "QEMU-Nyx/x86_64-softmmu/qemu-system-x86_64" ]; then
    cd QEMU-Nyx/ || return
    ./compile_qemu_nyx.sh lto || exit 1
    cd ..
fi

echo "[+] All done for nyx_mode, enjoy!"

exit 0
