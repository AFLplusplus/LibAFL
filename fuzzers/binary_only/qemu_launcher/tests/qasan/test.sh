#!/bin/bash
set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

if [[ ! -x "$QEMU_LAUNCHER" ]]; then
  echo "env variable QEMU_LAUNCHER does not point to a valid executable"
  echo "QEMU_LAUNCHER should point to qemu_launcher"
  exit 1
fi

cd "$SCRIPT_DIR"
make

tests=(
  "overflow"
  "underflow"
  "double_free"
  "memset"
  "uaf"
)

tests_expected=(
  "is 0 bytes to the right of the 10-byte chunk"
  "is 1 bytes to the left of the 10-byte chunk"
  "is 0 bytes inside the 10-byte chunk"
  "is 0 bytes to the right of the 10-byte chunk"
  "is 0 bytes inside the 10-byte chunk"
)

for i in "${!tests[@]}"
do
  test="${tests[i]}"
  expected="${tests_expected[i]}"

  echo "Running $test detection test..."
  OUT=$("$QEMU_LAUNCHER" \
    -r "inputs/$test.txt" \
    --input dummy \
    --output out \
    --asan-cores 0 \
    -- qasan 2>&1 | tr -d '\0')

  if echo "$OUT" | grep -q "$expected"; then
    echo "OK."
  else
    echo "ERROR: Output is"
    echo "$OUT"
    exit 1
  fi
done
