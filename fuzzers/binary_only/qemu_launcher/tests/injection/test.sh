#!/bin/bash
set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

if [[ ! -x "$QEMU_LAUNCHER" ]]; then
  echo "env variable QEMU_LAUNCHER does not point to a valid executable"
  echo "QEMU_LAUNCHER should point to qemu_launcher location, but points to ${QEMU_LAUNCHER} instead."
  exit 1
fi

cd "$SCRIPT_DIR"

make

mkdir in || true

echo aaaaaaaaaa > in/a

timeout 10s "$QEMU_LAUNCHER" -o out -i in -j ../../injections.toml -v -- ./static >/dev/null 2>fuzz.log || true
if ! grep -Ei "found.*injection" fuzz.log; then
    echo "Fuzzer does not generate any testcases or any crashes"
    echo "Logs:"
    cat fuzz.log
    exit 1
else
    echo "Fuzzer is working"
fi

make clean