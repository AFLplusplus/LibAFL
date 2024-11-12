#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
LIBAFL_DIR=$(realpath "$SCRIPT_DIR/..")

cd $LIBAFL_DIR

BLACKLIST=(
  "qemu_linux_process"
  "qemu_linux_kernel"
)

is_blacklisted() {
  local FUZZER="$1"
  for SUBSTRING in "${BLACKLIST[@]}"; do
    if [[ "$FUZZER" == *"$SUBSTRING" ]]; then
      return 0  # Blacklisted
    fi
  done
  return 1  # Not blacklisted
}

# Find all directories at depth 2 under ./fuzzers
find ./fuzzers -mindepth 2 -maxdepth 2 -type d | while read -r FUZZER; do

  if is_blacklisted $FUZZER; then
    echo "Skipping $FUZZER"
  else
    echo "Processing $FUZZER..."

    # Check if Makefile.toml exists in the fuzzer directory
    cd "$FUZZER" || { echo "Failed to enter directory $FUZZER"; continue; }
    if [ -f "./Makefile.toml" ]; then
      echo "Found Makefile.toml in $FUZZER. Running 'cargo make build'..."
      cargo make build || { echo "failed to build fuzzer $FUZZER"; code "$FUZZER/"; exit 1; }
    else
      echo "No Makefile.toml in $FUZZER. Running 'cargo build'..."
      cargo build || { echo "failed to build fuzzer $FUZZER"; code "$FUZZER/"; exit 1; }
    fi

    # Return to the LibAFL root directory
    cd $LIBAFL_DIR || { echo "Failed to return to LibAFL directory!"; exit 1; }
  fi
done