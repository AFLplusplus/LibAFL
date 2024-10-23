#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
cd "$SCRIPT_DIR/.." || exit 1

set -e
# Function to run Clippy on a single directory
run_clippy() {
   local dir="$1"
   local features="$2"
   echo "Running Clippy on $dir"
   pushd "$dir" || return 1

   RUST_BACKTRACE=full cargo +nightly clippy --all ${features:+"$features"} --no-deps --tests --examples --benches -- -Z macro-backtrace \
      -D clippy::all \
      -D clippy::pedantic \
      -W clippy::similar_names \
      -A clippy::type_repetition_in_bounds \
      -A clippy::missing-errors-doc \
      -A clippy::cast-possible-truncation \
      -A clippy::used-underscore-binding \
      -A clippy::ptr-as-ptr \
      -A clippy::missing-panics-doc \
      -A clippy::missing-docs-in-private-items \
      -A clippy::unseparated-literal-suffix \
      -A clippy::module-name-repetitions \
      -A clippy::unreadable-literal

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
RUST_BACKTRACE=full cargo +nightly clippy --all --no-deps --tests --examples --benches -- -Z macro-backtrace \
   -D clippy::all \
   -D clippy::pedantic \
   -W clippy::similar_names \
   -A clippy::type_repetition_in_bounds \
   -A clippy::missing-errors-doc \
   -A clippy::cast-possible-truncation \
   -A clippy::used-underscore-binding \
   -A clippy::ptr-as-ptr \
   -A clippy::missing-panics-doc \
   -A clippy::missing-docs-in-private-items \
   -A clippy::unseparated-literal-suffix \
   -A clippy::module-name-repetitions \
   -A clippy::unreadable-literal


# Loop through each project and run Clippy
for project in "${PROJECTS[@]}"; do
   # Trim leading and trailing whitespace
   project=$(echo "$project" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
   features="--all-features"
   if [[ " ${NO_ALL_FEATURES[*]} " =~ ${project} ]]; then
      features="--features=clippy"
   fi
   if [ -d "$project" ]; then
      run_clippy "$project" $features
   else
      echo "Warning: Directory $project does not exist. Skipping."
   fi
done

echo "Clippy run completed for all specified projects."
