#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
LIBAFL_DIR=$(realpath "$SCRIPT_DIR/..")

cd "${LIBAFL_DIR}" || exit 1

if [ "$1" = "check" ]; then
  cargo run --manifest-path "$LIBAFL_DIR/utils/libafl_fmt/Cargo.toml" --release -- -c --verbose || exit 1
else
  cargo run --manifest-path "$LIBAFL_DIR/utils/libafl_fmt/Cargo.toml" --release -- --verbose || exit 1
fi

if python3 -m black --version > /dev/null; then
  BLACK_COMMAND="python3 -m black"
elif command -v black > /dev/null; then
  BLACK_COMMAND="black"
fi

if [ -n "$BLACK_COMMAND" ]; then
  echo "[*] Formatting python files"
  if [ "$1" = "check" ]; then
    $BLACK_COMMAND --check --diff "$LIBAFL_DIR" || exit 1
  else
    $BLACK_COMMAND "$LIBAFL_DIR" || exit 1
  fi
else
  echo -e "\n\033[1;33mWarning\033[0m: python black not found. Formatting skipped for python.\n"
fi

if [ "$1" != "check" ]; then
  if command -v taplo > /dev/null; then
    echo "[*] Formatting TOML files"
    taplo format
  fi
fi

echo "[*] Done :)"
