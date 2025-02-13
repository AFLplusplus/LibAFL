#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.." || exit 1

set -e

cd libafl_derive
cargo publish "$@"
cd .. || exit 1

sleep 20

cd libafl_cc
cargo publish "$@"
cd .. || exit 1

sleep 20

cd libafl_bolts
cargo publish "$@"
cd .. || exit 1

sleep 20

cd libafl_intelpt
cargo publish "$@"
cd .. || exit 1

sleep 20

cd libafl
cargo publish "$@"
cd .. || exit 1

sleep 20

cd libafl_targets
cargo publish "$@"
cd .. || exit 1

sleep 20

cd libafl_frida
cargo publish "$@"
cd .. || exit 1

sleep 20

cd libafl_qemu

cd libafl_qemu_build
cargo publish "$@"
cd ..
cd libafl_qemu_sys
cargo publish "$@"
cd ..

cargo publish "$@"
cd .. || exit 1

sleep 20

cd libafl_sugar
cargo publish "$@"
cd .. || exit 1

sleep 20

cd libafl_concolic/symcc_libafl
cargo publish "$@"
cd ../.. || exit 1

sleep 20

# init symcc submodule if not already done
if git submodule status | grep "^-">/dev/null ; then \
    echo "Initializing submodules"; \
    git submodule init; \
    git submodule update; \
fi

cd libafl_concolic/symcc_runtime
cargo publish "$@" --allow-dirty
cd ../.. || exit 1

cd libafl_libfuzzer
cargo publish "$@"
cd .. || exit 1
