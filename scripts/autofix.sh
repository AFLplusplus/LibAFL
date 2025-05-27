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
cargo fix --release --workspace --all-features --allow-dirty --allow-staged

echo "[+] Done fixing build"
echo 

echo 'Fixing clippy (might need a "git commit" and a rerun, if "cargo fix" changed the source)'
RUST_BACKTRACE=full cargo clippy --fix --release --all --all-features --tests --examples --benches --allow-dirty --allow-staged --broken-code

cargo fmt

cargo clippy --fix --tests --examples --benches --all-features --allow-dirty --allow-staged --broken-code

cargo fmt

echo "[+] Done fixing clippy"
echo

echo "Formatting all"
"$SCRIPT_DIR/fmt_all.sh"