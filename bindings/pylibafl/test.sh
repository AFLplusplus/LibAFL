#!/usr/bin/env bash

mkdir in || true
echo "a" > ./in/a

timeout 10 python3 ./test.py
export exit_code=$?
if [ $exit_code -eq 124 ]; then
  # 124 = timeout happened. All good.
  exit 0
else
  exit $exit_code
fi

