this example shows to use `libafl_nyx` to fuzz `libxml2`

# requirement
1. dependency
you need afl-clang-fast to instruct `libxml2`. If you haven't install it in system path, you can do the following:
```
git clone https://github.com/AFLplusplus/AFLplusplus
cd ./AFLplusplus
make all # this will only make source-only part
```
then you would like to set up the shared directory and config file for nyx.
```
./setup_libxml2.sh
```

# run the fuzzer
use `cargo run` to run the fuzzer

