#!/usr/bin/env bash

# CI script for FreeBSD

set -x
set -e

curl https://sh.rustup.rs -sSf | sh -s -- -y
freebsd-version
source "$HOME/.cargo/env"
rustup toolchain install nightly
export LLVM_CONFIG=/usr/local/bin/llvm-config16
pwd
ls -lah
echo "local/bin"
ls -lah /usr/local/bin/
which llvm-config
chmod +x ./scripts/clippy.sh
bash ./scripts/shmem_limits_fbsd.sh
bash ./scripts/clippy.sh
cargo test