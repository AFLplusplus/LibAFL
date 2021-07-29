set -eux;

# this test intends to ...
# 1. compile symcc with the rust/tracing backend
# 2. compile a program using this symcc
# 3. run the program, capturing constraints
# 4. print the constraints in human readable form for verification

rm -rf symcc_build
mkdir symcc_build

cd symcc_build
cmake -G Ninja -DZ3_TRUST_SYSTEM_VERSION=on ../../libafl_symcc 
ninja
cd ..
cargo build -p runtime_test
SYMCC_RUNTIME_DIR=../../target/debug/ symcc_build/symcc ../libafl_symcc/test/if.c -o "if"

cargo run -p dump_constraints -- --plain-text --output constraints.txt -- ./if < if_test_input

cat constraints.txt