#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

set -e

cd libafl_derive
cargo publish $@
cd ..

sleep 20

cd libafl_cc
cargo publish $@
cd ..

sleep 20

cd libafl
cargo publish $@
cd ..

sleep 20

cd libafl_targets
cargo publish $@
cd ..

sleep 20

cd libafl_frida
cargo publish $@
cd ..

sleep 20

cd libafl_qemu
cargo publish $@
cd ..

sleep 20

cd libafl_sugar
cargo publish $@
cd ..

sleep 20

cd libafl_concolic/symcc_libafl
cargo publish $@
cd ../..

sleep 20

# init symcc submodule if not already done
if git submodule status | grep "^-">/dev/null ; then \
    echo "Initializing submodules"; \
    git submodule init; \
    git submodule update; \
fi

cd libafl_concolic/symcc_runtime
cargo publish $@
cd ../..
