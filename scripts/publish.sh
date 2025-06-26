#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.." || exit 1

set -e

pushd crates/libafl_derive
cargo publish "$@"
popd || exit 1

sleep 20

pushd crates/libafl_cc
cargo publish "$@"
popd || exit 1

sleep 20

pushd crates/libafl_bolts
cargo publish "$@"
popd || exit 1

sleep 20

pushd crates/libafl_intelpt
cargo publish "$@"
popd || exit 1

sleep 20

pushd crates/libafl
cargo publish "$@"
popd || exit 1

sleep 20

pushd crates/libafl_targets
cargo publish "$@"
popd || exit 1

sleep 20

pushd crates/libafl_frida
cargo publish "$@"
popd || exit 1

sleep 20

pushd crates/libafl_qemu

pushd libafl_qemu_build
cargo publish "$@"
popd
pushd libafl_qemu_sys
cargo publish "$@"
popd

cargo publish "$@"
popd || exit 1

sleep 20

pushd crates/libafl_sugar
cargo publish "$@"
popd || exit 1

sleep 20

pushd crates/libafl_concolic/symcc_libafl
cargo publish "$@"
popd || exit 1

sleep 20

# init symcc submodule if not already done
if git submodule status | grep "^-">/dev/null ; then \
    echo "Initializing submodules"; \
    git submodule init; \
    git submodule update; \
fi

pushd crates/libafl_concolic/symcc_runtime
cargo publish "$@" --allow-dirty
popd || exit 1

pushd crates/libafl_libfuzzer
cargo publish "$@"
popd || exit 1

sleep 20

pushd crates/libafl_asan
cargo publish "$@"
popd || exit 1

sleep 20

pushd crates/libafl_asan/libafl_asan_libc
cargo publish "$@"
popd || exit 1

sleep 20

pushd crates/libafl_qemu/libafl_qemu_asan/libafl_qemu_asan_guest
cargo publish "$@"
popd || exit 1

sleep 20

pushd crates/libafl_qemu/libafl_qemu_asan/libafl_qemu_asan_host
cargo publish "$@"
popd || exit 1

sleep 20

pushd crates/libafl_qemu/libafl_qemu_asan/libafl_qemu_asan_nolibc
cargo publish "$@"
popd || exit 1

sleep 20

pushd crates/libafl_qemu/libafl_qemu_runner
cargo publish "$@"
popd || exit 1