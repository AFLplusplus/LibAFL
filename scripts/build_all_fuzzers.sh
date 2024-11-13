#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.." || exit 1
# TODO: This should be rewritten in rust, a Makefile, or some platform-independent language

if [[ -z "${RUN_ON_CI}" ]]; then
    fuzzers=$(find ./fuzzers -mindepth 2 -maxdepth 2 -type d)
    backtrace_fuzzers=$(find ./fuzzers/baby/backtrace_baby_fuzzers -mindepth 1 -maxdepth 1 -type d)
else
    cargo build -p build_and_test_fuzzers
    fuzzers=$(cargo run -p build_and_test_fuzzers -- "remotes/origin/main" "HEAD^")
    backtrace_fuzzers=""
    export PROFILE=dev
    export PROFILE_DIR=debug
fi

fuzzers=$(echo "$fuzzers" | tr ' ' '\n')
backtrace_fuzzers=$(echo "$backtrace_fuzzers" | tr ' ' '\n')

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
    # export CARGO_PROFILE_"$profile"_INCREMENTAL=true
done

# shellcheck disable=SC2116
for fuzzer in $(echo "$fuzzers" "$backtrace_fuzzers");
do
    # skip nyx test on non-linux platforms
    if [[ $fuzzer == *"nyx_"* ]]; then
        continue
    fi

    cd "$fuzzer" || exit 1
    # Clippy checks
    echo "[*] Checking fmt for $fuzzer"
    cargo +nightly fmt --all || exit 1

    if [ -e ./Makefile.toml ]; then
        echo "[*] Building $fuzzer"
        cargo make build || exit 1
        echo "[+] Done building $fuzzer"
    else
        echo "[*] Building $fuzzer"
        cargo build || exit 1
        echo "[+] Done building $fuzzer"
    fi

    # no cleaning -- this is a local test, we want to cache here
    cd "$libafl" || exit 1
    echo ""
done
