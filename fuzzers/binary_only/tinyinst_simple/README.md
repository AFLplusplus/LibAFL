# Tinyinst example
This is a fuzzer example to show how libafl_tinyinst works.

## How to build
1. Install cxxbridge-cmd with `cargo install cxxbridge-cmd`
2. Build the harness with `cl test\test.cpp -o test.exe`
3. Build the fuzzer with `cargo build --release`. The fuzzer is `target\release\tinyinst_simple.exe`

## Run with just
Or, you can simply run it using just
1. If on Windows, open up a developer powershell so that you have access to cl (Windows Default Compiler)
2. Run `just run` to run the fuzzer
