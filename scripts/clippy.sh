#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

# Clippy checks
if [ "$1" != "--no-clean" ]; then
   # Usually, we want to clean, since clippy won't work otherwise.
   echo "[+] Cleaning up previous builds..."
   cargo clean -p libafl
fi
RUST_BACKTRACE=full cargo +nightly clippy --all --all-features --tests -- -Z macro-backtrace \
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
   -A clippy::unreadable-literal \
