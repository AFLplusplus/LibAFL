#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
cd "$SCRIPT_DIR/.." || exit 1

CLIPPY_CMD="RUST_BACKTRACE=full cargo clippy --no-deps --tests --examples --benches"

set -e
# Function to run Clippy on a single directory
run_clippy() {
   local dir="$1"
   local features="$2"
   echo "Running Clippy on $dir"
   echo "$CLIPPY_CMD ${features:+"$features"} -- $RUSTC_FLAGS"
   pushd "$dir" || return 1
   
   eval "$CLIPPY_CMD ${features:+"$features"} -- $RUSTC_FLAGS"

   popd || return 1
}

# Define projects based on the operating system
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
   ALL_PROJECTS=(
      "libafl"
      "libafl_bolts"
      "libafl_cc"
      "libafl_concolic/symcc_runtime"
      "libafl_concolic/symcc_libafl"
      "libafl_frida"
      "libafl_libfuzzer"
      "libafl_libfuzzer_runtime"
      "libafl_qemu"
      "libafl_tinyinst"
      "libafl_qemu/libafl_qemu_build"
      "libafl_qemu/libafl_qemu_sys"
      "libafl_nyx"
      "libafl_intelpt"
   )
fi

# Do not use --all-features for the following projects
NO_ALL_FEATURES=(
   "libafl_qemu"
)

if [ "$#" -eq 0 ]; then
   # No arguments provided, run on all projects
   PROJECTS=("${ALL_PROJECTS[@]}")
else
   # Arguments provided, split the input string into an array
   IFS=',' read -ra PROJECTS <<<"$1"
fi

# Loop through each project and run Clippy
for project in "${PROJECTS[@]}"; do
   # Trim leading and trailing whitespace
   project=$(echo "$project" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
   features="--all-features"
   for item in "${NO_ALL_FEATURES[@]}"; do
     if [[ "$item" == "$project" ]]; then
       features="--features=clippy"
     fi
   done
   if [ -d "$project" ]; then
      run_clippy "$project" "$features"
   else
      echo "Warning: Directory $project does not exist. Skipping."
   fi
done
# Last run it on all
eval "$CLIPPY_CMD --workspace -- $RUSTC_FLAGS"

echo "Clippy run completed for all specified projects."
