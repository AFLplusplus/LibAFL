#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.." || exit 1
# TODO: This should be rewritten in rust, a Makefile, or some platform-independent language


fuzzer_to_test="$1"
export PROFILE=dev
export PROFILE_DIR=debug

echo "Testing" "$fuzzer_to_test"

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
for fuzzer in $(echo "$fuzzer_to_test");
do
    # skip nyx test on non-linux platforms
    if [[ $fuzzer == *"nyx_"* ]] && [[ $(uname -s) != "Linux" ]]; then
        continue
    fi

    (
        cd "$fuzzer" || exit 1
        # Clippy checks
        if [ "$1" != "--no-clippy" ]; then
            echo "[*] Running clippy for $fuzzer"
            cargo clippy || exit 1
        else
            echo "[+] Skipping fmt and clippy for $fuzzer (--no-clippy specified)"
        fi

        if [ -e ./Makefile.toml ] && grep -qF "skip_core_tasks = true" Makefile.toml; then
            echo "[*] Building $fuzzer (running tests is not supported in this context)"
            just build || exit 1
            echo "[+] Done building $fuzzer"
        elif [ -e ./Makefile.toml ]; then
            echo "[*] Testing $fuzzer"
            just test || exit 1
            echo "[+] Done testing $fuzzer"
        elif [ -e ./Justfile ]; then
            echo "[*] Testing $fuzzer"
            just test || exit 1
            echo "[+] Done testing $fuzzer"
        else
            echo "[*] Building $fuzzer"
            cargo build || exit 1
            echo "[+] Done building $fuzzer"
        fi
    )
done
