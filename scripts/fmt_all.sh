#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
LIBAFL_DIR=$(realpath "$SCRIPT_DIR/..")

if [ "$1" = "check" ]; then
  cargo run --manifest-path "$LIBAFL_DIR/utils/libafl_fmt/Cargo.toml" --release -- -c --verbose
else
  cargo run --manifest-path "$LIBAFL_DIR/utils/libafl_fmt/Cargo.toml" --release -- --verbose
fi
