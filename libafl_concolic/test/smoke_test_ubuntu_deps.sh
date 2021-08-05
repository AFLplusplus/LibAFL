#!/bin/bash
# intends to install build dependencies for the smoke test on ubuntu
set -eux;

apt install -y clang cmake llvm-dev ninja-build pkg-config zlib1g-dev