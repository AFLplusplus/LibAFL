#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
cd "$SCRIPT_DIR/.." || exit 1

# Update LibAFL QEMU bindings
pushd crates/libafl_qemu
  LIBVHARNESS_GEN_STUBS=1 LIBAFL_QEMU_GEN_STUBS=1 cargo +nightly build || exit 1
popd