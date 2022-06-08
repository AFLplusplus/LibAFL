#!/bin/bash
echo "================================================="
echo "           Nyx build script"
echo "================================================="
echo

echo "[*] Performing basic sanity checks..."

if [ ! "$(uname -m)" = "Linux" ]; then

  echo "[-] Error: Nyx mode is only available on Linux."
  exit 0

fi

if [ ! "$(uname -m)" = "x86_64" ]; then

  echo "[-] Error: Nyx mode is only available on x86_64 (yet)."
  exit 0

fi

echo "[*] Making sure all Nyx is checked out"

git status 1>/dev/null 2>/dev/null

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
    ./compile_qemu_nyx.sh static || exit 1
    cd ..
fi

echo "[*] Checking libnyx.so ..."
if [ -f "../target/release/liblibnyx.so" ]; then
  cp -v ../target/debug/liblibnyx.so ../libnyx.so || exit 1
elif [ -f "../target/release/liblibnyx.so" ]; then
  cp -v ../target/debug/liblibnyx.so ../libnyx.so || exit 1
  exit 1
fi
echo "[+] All done for nyx_mode, enjoy!"

exit 0
