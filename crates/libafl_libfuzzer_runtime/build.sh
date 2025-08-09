#!/bin/bash

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd "${SCRIPT_DIR}" || exit 1

#!/bin/bash

# Default values
profile="release"
toolchain="nightly"
cargoargs=""
rustcargs=""
ccompilerflags=""

# Help message
print_help() {
  echo "Usage: $0 [options]"
  echo
  echo "Options:"
  echo "  -p, --profile         Build profile to use (default: release)"
  echo "  -t, --toolchain       Toolchain to use (default: nightly)"
  echo "  -c, --cargo-args      Additional cargo arguments to pass"
  echo "  -r, --rustc-args      Additional rustc arguments to pass"
  echo "  -f, --cc-flags        Additional flags to set for the C compiler"
  echo "  -h, --help            Show this help message and exit"
  echo
  echo "Example:"
  echo "  $0 --profile dev --toolchain nightly --cargo-args \"--verbose\" --rustc-args \"--emit asm\" --cc-flags \"-O2\""
}

# Use getopt for long options
OPTIONS=$(getopt -o p:t:c:r:f:h --long profile:,toolchain:,cargo-args:,rustc-args:,cc-flags:,help -- "$@")
if [ $? -ne 0 ]; then
  echo "Invalid options provided"
  exit 1
fi
eval set -- "$OPTIONS"

# Parse options
while true; do
  case "$1" in
    -p|--profile)
      profile="$2"
      shift 2
      ;;
    -t|--toolchain)
      toolchain="$2"
      shift 2
      ;;
    -c|--cargo-args)
      cargoargs="$2"
      shift 2
      ;;
    -r|--rustc-args)
      rustcargs="$2"
      shift 2
      ;;
    -f|--cc-flags)
      ccompilerflags="$2"
      shift 2
      ;;
    -h|--help)
      print_help
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "Unexpected option: $1"
      exit 1
      ;;
  esac
done

if ! cargo +$toolchain --version >& /dev/null; then
  echo -e "You must install a recent Rust to build the libafl_libfuzzer runtime!"
  exit 1
fi

export RUSTFLAGS="${RUSTFLAGS} ${rustcargs}"
export CFLAGS="${CFLAGS} ${ccompilerflags}"
cargo +$toolchain build --profile "$profile" ${cargoargs}

if [[ "$OSTYPE" == "darwin"* ]]; then
  # MacOS and iOS
  "${CXX:-clang++}" -dynamiclib -Wl,-force_load target/release/libafl_libfuzzer_runtime.a  \
    -Wl,-U,_LLVMFuzzerInitialize -Wl,-U,_LLVMFuzzerCustomMutator -Wl,-U,_LLVMFuzzerCustomCrossOver -Wl,-U,_libafl_main \
    -o libafl_libfuzzer_runtime.dylib
else
  # Linux and *BSD
  RUSTC_BIN="$(cargo +$toolchain rustc -Zunstable-options --print target-libdir)/../bin"
  RUST_LLD="${RUSTC_BIN}/rust-lld"
  RUST_AR="${RUSTC_BIN}/llvm-ar"

  if ! [ -f "${RUST_LLD}" ] && [ -f "${RUST_AR}" ]; then
    echo -e "You must install the llvm-tools component: \`rustup component add llvm-tools'"
    exit 1
  fi

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
fi

