#!/bin/bash

set -x

mv libafl_libfuzzer_runtime/Cargo.toml libafl_libfuzzer_runtime/Cargo.toml.orig
cargo publish --allow-dirty --no-verify "$@"
mv libafl_libfuzzer_runtime/Cargo.toml.orig libafl_libfuzzer_runtime/Cargo.toml
