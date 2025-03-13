#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
LIBAFL_DIR=$(realpath "$SCRIPT_DIR/..")

cd "${LIBAFL_DIR}" || exit 1

cargo run --manifest-path "$LIBAFL_DIR/utils/libafl_repo_tools/Cargo.toml" --release -- --generate-lockfiles --verbose || exit 1

echo "[*] Done :)"
