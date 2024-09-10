#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
cd "$SCRIPT_DIR/.." || exit 1

set -e
# Function to run Clippy on a single directory
run_clippy() {
   local dir="$1"
   local all_features="$2"
   echo "All features: $all_features"
   echo "Running Clippy on $dir"
   pushd "$dir" || return 1

  CLIPPY_CMD="RUST_BACKTRACE=full cargo +nightly clippy --all ${all_features:+"$all_features"} --no-deps --tests --examples --benches -- -Z macro-backtrace"
  eval "$CLIPPY_CMD"

   popd || return 1
}

# Define projects based on the operating system
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
   ALL_PROJECTS=(
      "libafl_concolic/symcc_runtime"
      "libafl_concolic/symcc_libafl"
      "libafl_frida"
      "libafl_libfuzzer"
      "libafl_nyx"
      "libafl_qemu"
      "libafl_tinyinst"
      "libafl_qemu/libafl_qemu_build"
      "libafl_qemu/libafl_qemu_sys"
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

# First run it on all
run_clippy "./" "--all-features"

# Loop through each project and run Clippy
for project in "${PROJECTS[@]}"; do
   # Trim leading and trailing whitespace
   project=$(echo "$project" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
   all_features="--all-features"
   if [[ " ${NO_ALL_FEATURES[*]} " =~ ${project} ]]; then
      all_features="--features=clippy"
   fi
   if [ -d "$project" ]; then
      run_clippy "$project" $all_features
   else
      echo "Warning: Directory $project does not exist. Skipping."
   fi
done

echo "Clippy run completed for all specified projects."
