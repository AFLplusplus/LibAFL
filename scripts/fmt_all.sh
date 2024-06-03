#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
LIBAFL_DIR=$(realpath "$SCRIPT_DIR/..")

# TODO: This should be rewritten in rust, a Makefile, or some platform-independent language

if ! command -v parallel > /dev/null; then
    echo "Parallel could not be found. Please install parallel (often found in the 'moreutils' package)."
    exit 1
fi

if [ "$1" = "check" ]; then
  CHECK=1
fi

# Find main rust crates
CRATES_TO_FMT=$(find "$LIBAFL_DIR" -type d \( -path "*/fuzzers/*" -o -path "*/target/*" -o -path "*/utils/noaslr" -o -path "*/utils/gdb_qemu" -o -path "*/docs/listings/baby_fuzzer/listing-*" \) -prune \
  -o -name "Cargo.toml" -print \
  | grep -v "$LIBAFL_DIR/Cargo.toml")$'\n'

# Find fuzzer crates
CRATES_TO_FMT+=$(find "$LIBAFL_DIR/fuzzers" "$LIBAFL_DIR/fuzzers/backtrace_baby_fuzzers" "$LIBAFL_DIR/libafl_libfuzzer/libafl_libfuzzer_runtime" -maxdepth 2 -name "Cargo.toml" -print)

echo "Welcome to the happy fmt script. :)"

if [ "$CHECK" ]; then
  echo "Running fmt in check mode."
  CARGO_FLAGS="--check"
  CLANG_FLAGS="--dry-run"
fi

echo "[*] Formatting Rust crates..."
if ! echo "$CRATES_TO_FMT" | parallel --halt-on-error 1 "echo '[*] Running fmt for {}'; cargo +nightly fmt $CARGO_FLAGS --manifest-path {}"
then
  echo "Rust format failed."
  exit 1
fi

if command -v clang-format-18 > /dev/null; then
  echo "[*] Formatting C(pp) files"

  C_FILES=$(find "$LIBAFL_DIR" -type f \( -name '*.cpp' -o -iname '*.hpp' -o -name '*.cc' -o -name '*.cxx' -o -name '*.cc' -o -name '*.c' -o -name '*.h' \) | grep -v '/target/' | grep -v 'libpng-1\.6\.37' | grep -v 'stb_image\.h' | grep -v 'dlmalloc\.c' | grep -v 'QEMU-Nyx')
  if ! clang-format-18 "$CLANG_FLAGS" -i --style=file "$C_FILES"
  then
    echo "C(pp) format failed."
    exit 1
  fi

else
  echo "Warning: clang-format-18 not found. C(pp) files formatting skipped."
fi

if command -v black > /dev/null; then
  echo "[*] Formatting python files"
  if ! black "$SCRIPT_DIR"
  then
    echo "Python format failed."
    exit 1
  fi

else
  echo "Warning: clang-format-18 not found. C(pp) files formatting skipped."
fi

echo "[*] Done :)"
