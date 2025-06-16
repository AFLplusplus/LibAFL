#!/bin/bash
set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Set debug variable to let the target print stderr.
export LIBAFL_FUZZBENCH_DEBUG=1

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
  "test_limits"
)

tests_expected=(
  "AddressSanitizer Error"
  "AddressSanitizer Error"
  "Panic!"
  "AddressSanitizer Error"
  "AddressSanitizer Error"
  "Test-Limits - No Error"
)

tests_not_expected=(
  "dummy"
  "dummy"
  "dummy"
  "dummy"
  "dummy"
  "Context:"
)

# We don't want any core dumps. They can potentially be quite large
ulimit -c 0

for i in "${!tests[@]}"
do
  test="${tests[i]}"
  expected="${tests_expected[i]}"
  not_expected="${tests_not_expected[i]}"

  echo "Running $test detection test..."
  OUT=$("$QEMU_LAUNCHER" \
    -r "inputs/$test.txt" \
    --input dummy \
    --output out \
    --asan-host-cores 0 \
    -- qasan 2>&1 | tr -d '\0')

  if ! echo "$OUT" | grep -q "$expected"; then
    echo "ERROR: Expected: $expected."
    echo "Output is:"
    echo "$OUT"
    exit 1
  elif echo "$OUT" | grep -q "$not_expected"; then
    echo "ERROR: Did not expect: $not_expected."
    echo "Output is:"
    echo "$OUT"
    exit 1
  else
    echo "OK."
  fi
done
