#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.." || exit 1
# TODO: This should be rewritten in rust, a Makefile, or some platform-independent language


if [[ -z "${RUN_ON_CI}" ]]; then
    fuzzers=$(find ./fuzzers -mindepth 1 -maxdepth 1 -type d)
    backtrace_fuzzers=$(find ./fuzzers/backtrace_baby_fuzzers -mindepth 1 -maxdepth 1 -type d)
else
    cargo build -p build_and_test_fuzzers
    fuzzers=$(cargo run -p build_and_test_fuzzers -- "remotes/origin/main" "HEAD^")
    backtrace_fuzzers=""
    export PROFILE=dev
    export PROFILE_DIR=debug
fi

if [[ -n "${RUN_FUZZBENCH_FUZZER}" ]]; then
    fuzzers=$(echo "$fuzzers" | tr ' ' '\n' | grep "fuzzbench")
    backtrace_fuzzers=$(echo "$backtrace_fuzzers" | tr ' ' '\n' | grep "fuzzbench")
elif [[ -n "${RUN_QEMU_FUZZER}" ]]; then
    fuzzers=$(echo "$fuzzers" | tr ' ' '\n' | grep "qemu")
    backtrace_fuzzers=$(echo "$backtrace_fuzzers" | tr ' ' '\n' | grep "qemu")
elif [[ -n "${RUN_BABY_FUZZER}" ]]; then
    fuzzers=$(echo "$fuzzers" | tr ' ' '\n' | grep "baby")
    backtrace_fuzzers=$(echo "$backtrace_fuzzers" | tr ' ' '\n' | grep "baby")
elif [[ -n "${RUN_LIBPNG_FUZZER}" ]]; then
    fuzzers=$(echo "$fuzzers" | tr ' ' '\n' | grep "libpng")
    backtrace_fuzzers=$(echo "$backtrace_fuzzers" | tr ' ' '\n' | grep "libpng")
else
    fuzzers=$(echo "$fuzzers" | tr ' ' '\n' | grep -v "qemu" | grep -v "baby" | grep -v "libpng" | grep -v "fuzzbench")
    backtrace_fuzzers=$(echo "$backtrace_fuzzers" | tr ' ' '\n' | grep -v "qemu" | grep -v "baby" | grep -v "libpng" | grep - v "fuzzbench")
fi

libafl=$(pwd)

# build with a shared target dir for all fuzzers. this should speed up
# compilation a bit, and allows for easier artifact management (caching and
# cargo clean).
export CARGO_TARGET_DIR="$libafl/target"
mkdir -p "$CARGO_TARGET_DIR"

git submodule init && git submodule update

# override default profile settings for speed
# export RUSTFLAGS="-C prefer-dynamic"
for profile in DEV RELEASE; # loop for all profiles
do
    export CARGO_PROFILE_"$profile"_OPT_LEVEL=z # optimize for size
    # runs into shared target dir bug:
    # [pid 351769] openat(AT_FDCWD, "LibAFL/target/release/deps/libc-dbff77a14da5d893.libc.5deb7d4a-cgu.0.rcgu.dwo", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
    # error: failed to build archive: No such file or directory
    # export CARGO_PROFILE_"$profile"_SPLIT_DEBUGINFO=unpacked # minimize debug info
    # export CARGO_PROFILE_"$profile"_PANIC=abort
    export CARGO_PROFILE_"$profile"_INCREMENTAL=true
done

# shellcheck disable=SC2116
for fuzzer in $(echo "$fuzzers" "$backtrace_fuzzers");
do
    # skip nyx test on non-linux platforms
    if [[ $fuzzer == *"nyx_"* ]] && [[ $(uname -s) != "Linux" ]]; then
        continue
    fi

    cd "$fuzzer" || exit 1
    # Clippy checks
    if [ "$1" != "--no-fmt" ]; then
        
        echo "[*] Checking fmt for $fuzzer"
        cargo fmt --all -- --check || exit 1
        echo "[*] Running clippy for $fuzzer"
        cargo clippy || exit 1
    else
        echo "[+] Skipping fmt and clippy for $fuzzer (--no-fmt specified)"
    fi
    
    if [ -e ./Makefile.toml ] && grep -qF "skip_core_tasks = true" Makefile.toml; then
        echo "[*] Building $fuzzer (running tests is not supported in this context)"
        cargo make build || exit 1
        echo "[+] Done building $fuzzer"
    elif [ -e ./Makefile.toml ]; then
        echo "[*] Testing $fuzzer"
        cargo make test || exit 1
        echo "[+] Done testing $fuzzer"
    else
        echo "[*] Building $fuzzer"
        cargo build || exit 1
        echo "[+] Done building $fuzzer"
    fi
    du -sh "$CARGO_TARGET_DIR"
    # Save disk space
    cargo clean -p "$(basename "$fuzzer")"
    cargo clean --release -p "$(basename "$fuzzer")" 2> /dev/null
    # Leaving these in the cache results in lots of duplicate build artifacts
    # (many different feature flag combinations, ...), so let's prune them.
    for clean_pkgid in libafl libafl_targets libafl_sugar; do
        cargo clean -p "$clean_pkgid" 2> /dev/null
        cargo clean --release -p "$clean_pkgid" 2> /dev/null
    done
    du -sh "$CARGO_TARGET_DIR"
    cd "$libafl" || exit 1
    echo ""
done
