#!/bin/bash

ret=0

while read -r fuzzdir; do
  if ! grep -qa "$fuzzdir" .github/workflows/build_and_test.yml; then
    ret=1
    echo "Missing fuzzer ${fuzzdir} in CI tests!"
  fi
  if grep -qa "# - $fuzzdir" .github/workflows/build_and_test.yml; then
    echo "Fuzzer ${fuzzdir} is explicitly ignored"
  fi
done < <(
          find ./fuzzers -mindepth 2 -maxdepth 2 -type d
          find ./fuzzers/baby/backtrace_baby_fuzzers -mindepth 1 -maxdepth 1 -type d
        )

while read -r fuzzdir; do
  if ! grep -qa "$fuzzdir" justfile; then
    ret=1
    echo "Missing fuzzer ${fuzzdir} in justfile!"
  fi
  if grep -qa "nop \"$fuzzdir" justfile; then
    echo "Fuzzer ${fuzzdir} is explicitly ignored in justfile"
  fi
done < <(
          find ./fuzzers -mindepth 2 -maxdepth 2 -type d
          find ./fuzzers/baby/backtrace_baby_fuzzers -mindepth 1 -maxdepth 1 -type d
        )

exit $ret
