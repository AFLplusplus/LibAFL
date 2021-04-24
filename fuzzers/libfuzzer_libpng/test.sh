cargo build --release
./target/release/libafl_cxx ./harness.cc libpng-1.6.37/.libs/libpng16.a -I libpng-1.6.37/ -o fuzzer_libpng -lz -lm

taskset -c 0 ./fuzzer_libpng &
sleep 1
taskset -c 1 ./fuzzer_libpng 2>/dev/null


killall ./fuzzer_libpng
rm -rf ./fuzzer_libpng
