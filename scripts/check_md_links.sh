#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
LIBAFL_DIR=$(realpath "$SCRIPT_DIR/..")

echo "[*] Checking MD links..."

cd "$LIBAFL" || exit 1

if ! command -v linkspector > /dev/null; then
  echo "Error: install linkspector to check MD file links."
  exit 1
fi

linkspector check -c "${LIBAFL_DIR}/.github/.linkspector.yml" || exit 1

echo "[*] Done :)"
