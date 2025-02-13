#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.." || exit 1

# Clippy checks
if [ "$1" != "--no-clean" ]; then
   # Usually, we want to clean, since clippy won't work otherwise.
   echo "[+] Cleaning up previous builds..."
   cargo clean -p libafl
fi
echo 

echo "[+] Fixing build"
cargo +nightly fix --release --workspace --all-features --allow-dirty --allow-staged

echo "[+] Done fixing build"
echo 

echo 'Fixing clippy (might need a "git commit" and a rerun, if "cargo fix" changed the source)'
RUST_BACKTRACE=full cargo +nightly clippy --fix --release --all --all-features --tests --examples --benches --allow-dirty --allow-staged -- -Z macro-backtrace \
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

cargo +nightly clippy --fix --tests --examples --benches --all-features --allow-dirty --allow-staged

echo "[+] Done fixing clippy"
echo

echo "Formatting all"
"$SCRIPT_DIR/fmt_all.sh"