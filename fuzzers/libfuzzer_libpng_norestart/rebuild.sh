cargo build --release
cd ./libpng-1.6.37
make CC=../target/release/libafl_cc CXX=../target/release/libafl_cxx -j 16
cd ..
./target/release/libafl_cxx ./harness.cc libpng-1.6.37/.libs/libpng16.a -I libpng-1.6.37/ -o fuzzer_libpng -lz -lm
echo "ready"
