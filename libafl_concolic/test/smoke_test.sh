#!/bin/bash
set -eux;

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

# this test intends to ...
# 1. compile symcc with the rust/tracing backend
# 2. compile a program using this symcc
# 3. run the program, capturing constraints
# 4. print the constraints in human readable form for verification
# 5. check that the captured constraints match those that we expect

# clone symcc
if [ ! -d "symcc" ]; then
    echo "cloning symcc"
    git clone https://github.com/AFLplusplus/symcc.git symcc
    cd symcc
    git checkout 1330e29d28bce706d9f7c0864da3b0a5ae218e03
    cd ..
fi

if [ ! -d "symcc_build" ]; then
    echo "building symcc"
    mkdir symcc_build
    cd symcc_build
    cmake -G Ninja -DZ3_TRUST_SYSTEM_VERSION=on ../symcc 
    ninja
    cd ..
fi


echo "building runtime and dump_constraints"
cargo build -p runtime_test -p dump_constraints

echo "building target"
SYMCC_RUNTIME_DIR=../../target/debug symcc_build/symcc symcc/test/if.c -o "if"

echo "running target with dump_constraints"
cargo run -p dump_constraints -- --plain-text --output constraints.txt -- ./if < if_test_input

echo "constraints: "
cat constraints.txt

# site_id's in the constraints trace will differ for every run. we therefore filter those.
sed 's/, location: .* / /' < constraints.txt > constraints_filtered.txt
sed 's/, location: .* / /' < expected_constraints.txt > expected_constraints_filtered.txt

diff constraints_filtered.txt expected_constraints_filtered.txt
