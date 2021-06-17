set -eux;

# this test intends to compile symcc with the rust backend, compile a program using this symcc and run it

rm -rf symcc_build
mkdir symcc_build

cd symcc_build
cmake -G Ninja -DRUST_BACKEND=YES ../../libafl_symcc 
ninja
cd ..
symcc_build/symcc ../libafl_symcc/test/if.c -o "if"

# this is expected to fail, because the runtime can't locate the shared memory mapping
./if || true 
