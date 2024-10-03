#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.." || exit 1

set -e

RUST_BACKTRACE=full cargo +nightly clippy --all --all-features --exclude libafl_nyx --exclude symcc_runtime --exclude runtime_test --no-deps --tests --examples --benches -- -Z macro-backtrace \
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
