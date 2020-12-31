#!/bin/sh

cargo build --release

git submodule init
git submodule update qemu_fuzz

cd qemu-fuzz

./build_qemu_fuzz.sh ../target/release/libqemufuzzer.a

cp build/qemu-x86_64 ../qemu_fuzz
