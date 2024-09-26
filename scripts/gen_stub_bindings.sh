#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
LIBAFL_DIR=$(realpath "$SCRIPT_DIR/..")

export LIBAFL_QEMU_GEN_STUBS=1

cd "${LIBAFL_DIR}/libafl_qemu" || exit 1
cargo build
