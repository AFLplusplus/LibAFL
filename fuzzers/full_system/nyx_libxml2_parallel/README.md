this example shows to use `libafl_nyx` to fuzz `libxml2`

# requirement
the following command will:
1. run `cargo build --release` to generate `libafl_cc`,`libafl_cxx`
2. download and extract `libxml2`
3. instruct `libxml2` using `libafl_cc` and `libafl_cxx`
4. prepare nyx shared dir and config file at `/tmp/nyx_libxml2`
5. open kvm support
```
./setup_libxml2.sh
```

# run the fuzzer
use `just run` to run the fuzzer. If you have setup all environment, you can use `cargo run` directly.
