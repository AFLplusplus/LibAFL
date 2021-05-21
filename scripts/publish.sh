#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

set -e

cd libafl_derive
cargo publish $@
cd ..

sleep 2

cd libafl_cc
cargo publish $@
cd ..

sleep 2

cd libafl
cargo publish $@
cd ..

sleep 2

cd libafl_targets
cargo publish $@
cd ..

sleep 2

cd libafl_frida
cargo publish $@
cd ..
