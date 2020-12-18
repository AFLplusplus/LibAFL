#!/bin/sh

cargo build --release

cd qemu-fuzz

git submodule update

./build_qemu_fuzz.sh ../target/release/libqemufuzzer.a

cp build/qemu-x86_64 ../qemu_fuzz

