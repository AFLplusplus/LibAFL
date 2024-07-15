#!/bin/bash

# Check if an argument is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <comma-separated list of directories>"
    exit 1
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.." || exit 1

# Function to run Clippy on a single directory
run_clippy() {
    local dir="$1"
    echo "Running Clippy on $dir"
    pushd "$dir" || return 1

    RUST_BACKTRACE=full cargo +nightly clippy --all --all-features --no-deps --tests --examples --benches -- -Z macro-backtrace \
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

    # Check if we're on Linux and if libafl_libfuzzer_runtime exists
    if [[ "$OSTYPE" == "linux-gnu"* ]] && [ -d "libafl_libfuzzer/libafl_libfuzzer_runtime" ]; then
        echo "Running Clippy on libafl_libfuzzer_runtime"
        cd libafl_libfuzzer/libafl_libfuzzer_runtime || return 1
        RUST_BACKTRACE=full cargo +nightly clippy --all --all-features --no-deps --tests --examples --benches -- -Z macro-backtrace \
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
    fi

    popd || return 1
}

# Split the input string into an array
IFS=',' read -ra PROJECTS <<< "$1"

# Loop through each project and run Clippy
for project in "${PROJECTS[@]}"; do
   # Trim leading and trailing whitespace
   project=$(echo "$project" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
   if [ -d "$project" ]; then
       run_clippy "$project"
   else
       echo "Warning: Directory $project does not exist. Skipping."
   fi
done

echo "Clippy run completed for all specified projects."