#!/bin/bash

# Script to find .rs files that don't get built.

cargo +nightly build --examples --all-features --tests --examples --benches

# Find all files in deps, then compare to all actual .d files. Ignore a range of files.
grep --no-filename '^[^/].*\.rs:$' target/debug/deps/*.d | sed 's/:$//' | sort -u | diff - <(find . -name '*.rs' | sed 's/\.\///' | sort -u) | grep -Ev '(target/|scripts/|symcc_runtime/|build.rs|fuzzers/)'