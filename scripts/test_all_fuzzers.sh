#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.." || exit 1

# TODO: This should be rewritten in rust, a Makefile, or some platform-independent language

fuzzers=$(find ./fuzzers -mindepth 1 -maxdepth 1 -type d)
backtrace_fuzzers=$(find ./fuzzers/backtrace_baby_fuzzers -mindepth 1 -maxdepth 1 -type d)

libafl=$(pwd)

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

# record time of each fuzzer
declare -A time_record || (echo "declare -A not avaliable, please update your bash version to 4";exit 1)

# shellcheck disable=SC2116
for fuzzer in $(echo "$fuzzers" "$backtrace_fuzzers");
do
    # for nyx examples
    if [[ $fuzzer == *"nyx_"* ]]; then
    
    	# only test on linux
    	if [[ $(uname -s) == "Linux" ]]; then
		    cd "$fuzzer" || exit 1
			if [ "$1" != "--no-fmt" ]; then
			    echo "[*] Checking fmt for $fuzzer"
			    cargo fmt --all -- --check || exit 1
			    echo "[*] Running clippy for $fuzzer"
			    cargo clippy || exit 1
			else
			    echo "[+] Skipping fmt and clippy for $fuzzer (--no-fmt specified)"
			fi
            cargo make build
		    cd - || exit
	    fi
        continue
    fi

    cd "$fuzzer" || exit 1
    start=$(date +%s)
    # Clippy checks
    if [ "$1" != "--no-fmt" ]; then
        
        echo "[*] Checking fmt for $fuzzer"
        cargo fmt --all -- --check || exit 1
        echo "[*] Running clippy for $fuzzer"
        cargo clippy || exit 1
    else
        echo "[+] Skipping fmt and clippy for $fuzzer (--no-fmt specified)"
    fi
    
    if [ -e ./Makefile.toml ]; then
        echo "[*] Testing $fuzzer"
        cargo make test || exit 1
	    echo "[+] Done testing $fuzzer"
    else
        echo "[*] Building $fuzzer"
        cargo build || exit 1
        echo "[+] Done building $fuzzer"
    fi
    end=$(date +%s)
    time_record[$fuzzer]=$((end-start))
    du -sh "$CARGO_TARGET_DIR"
    # Save disk space
    cargo clean -p "$(basename "$fuzzer")"
    cargo clean --release -p "$(basename "$fuzzer")" 2> /dev/null
    # Leaving these in the cache results in lots of duplicate build artefacts
    # (many different feature flag combinations, ...), so let's prune them.
    for clean_pkgid in libafl libafl_targets libafl_sugar; do
        cargo clean -p "$clean_pkgid" 2> /dev/null
        cargo clean --release -p "$clean_pkgid" 2> /dev/null
    done
    du -sh "$CARGO_TARGET_DIR"
    cd "$libafl" || exit 1
    echo ""
done

# print time for each fuzzer
for key in "${!time_record[@]}"; do
    echo "dir: $key, time: ${time_record[$key]}";
done
