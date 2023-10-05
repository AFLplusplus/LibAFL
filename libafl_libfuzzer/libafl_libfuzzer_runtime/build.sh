#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd "${SCRIPT_DIR}" || exit 1

if ! cargo +nightly --version >& /dev/null; then
  echo -e "You must install a recent Rust nightly to build the libafl_libfuzzer runtime!"
  exit 1
fi

RUSTC_BIN="$(cargo +nightly rustc -Zunstable-options --print target-libdir)/../bin"
RUST_LLD="${RUSTC_BIN}/rust-lld"
RUST_AR="${RUSTC_BIN}/llvm-ar"

if ! [ -f "${RUST_LLD}" ] && [ -f "${RUST_AR}" ]; then
  echo -e "You must install the llvm-tools component: \`rustup component add llvm-tools'"
  exit 1
fi

cargo +nightly build --release

tmpdir=""

cleanup() {
    rm -rf "${tmpdir}"
    exit
}
trap cleanup INT TERM

tmpdir="$(mktemp -d)"
"${RUST_LLD}" -flavor gnu -r --whole-archive target/release/libafl_libfuzzer_runtime.a -o "${tmpdir}/libFuzzer.o"
"${RUST_AR}" cr libFuzzer.a "${tmpdir}/libFuzzer.o"

echo "Done! Wrote the runtime to \`${SCRIPT_DIR}/libFuzzer.a'"
cleanup
