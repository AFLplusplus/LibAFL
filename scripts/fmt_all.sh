#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
LIBAFL_DIR=$(realpath "$SCRIPT_DIR/..")

if [ "$1" = "check" ]; then
  cargo run --manifest-path "$LIBAFL_DIR/utils/libafl_fmt/Cargo.toml" --release -- -c --verbose || exit 1
else
  cargo run --manifest-path "$LIBAFL_DIR/utils/libafl_fmt/Cargo.toml" --release -- --verbose || exit 1
fi

if command -v black > /dev/null; then
  echo "[*] Formatting python files"
  if ! black "$SCRIPT_DIR"
  then
    echo "Python format failed."
    exit 1
  fi

else
  echo "Warning: python black not found. Formatting skipped for python."
fi

echo "[*] Done :)"
