export ROOT_DIR := justfile_directory()
export SCRIPTS_DIR := join(justfile_directory(), "scripts")
export FUZZERS_DIR := join(justfile_directory(), "fuzzers")
export TARGET_DIR := join(justfile_directory(), "target")
export DOCS_DIR := join(justfile_directory(), "docs")
export LIBAFL_DIR := join(justfile_directory(), "libafl")
export LIBAFL_BOLTS_DIR := join(justfile_directory(), "libafl_bolts")
export LIBAFL_TARGETS_DIR := join(justfile_directory(), "libafl_targets")

MSRV := env_var_or_default('MSRV', "")

# Check, build, and test all crates with default features enabled
default feature='' ignore='': (check feature ignore) (build feature ignore) (test feature ignore)

# Check, build, and test all crates with all-features enabled
all-features: (default "--all-features")

# Build examples
examples: (default "--examples")

# Check, build, and test all crates with no-default-features
no-default-features: (default "--no-default-features")

# Run check on all projects in the workspace
check feature='' ignore='':
    cargo ws exec {{ignore}} cargo {{MSRV}} check --locked --all-targets {{feature}}
    cargo {{MSRV}} check --manifest-path fuzz/Cargo.toml --locked --all-targets

# Run build on all projects in the workspace
build feature='' ignore='':
    cargo ws exec {{ignore}} cargo {{MSRV}} build --locked --all-targets {{feature}}

# Run tests on all projects in the workspace
test feature='' ignore='':
    cargo ws exec {{ignore}} cargo {{MSRV}} test --locked --all-targets {{feature}}

# Runs tests without default features (for no_std)
test-no-std:
    cd {{LIBAFL_DIR}} && cargo test --no-default-features
    cd {{LIBAFL_BOLTS_DIR}} && cargo test --no-default-features
    cd {{LIBAFL_TARGETS_DIR}} && cargo test --no-default-features
    cd {{FUZZERS_DIR}}/fuzz_anything/baby_no_std && cargo +nightly run || test $? -ne 0 || exit 1

# Build the fuzzer on aarch64 none
build-aarch64-unknown-none:
    cd {{LIBAFL_BOLTS_DIR}} && cargo +nightly build -Zbuild-std=core --target aarch64-unknown-none --no-default-features -v --release
    cd {{FUZZERS_DIR}}/fuzz_anything/baby_no_std && cargo +nightly build -Zbuild-std=core,alloc --target aarch64-unknown-none -v --release

clippy-thumbv6m-none-eabi:
    cd {{LIBAFL_DIR}} && cargo clippy --target thumbv6m-none-eabi --no-default-features

# Builds the docs
doc feature='':
    cargo ws exec cargo {{MSRV}} test --locked --doc {{feature}} --test-threads 1
    RUSTFLAGS="--cfg docsrs" cargo +nightly doc --all-features --no-deps

# Tests the code using miri
test-miri:
    RUST_BACKTRACE=1 MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test

# Tests all code in docs (macos version)
[private]
[macos]
test-docs-internal: all-features
    cd {{DOCS_DIR}} && mdbook test -L ../target/debug/deps $(python3-config --ldflags | cut -d ' ' -f1)

# Tests all code in docs (linux version)
[private]
[linux]
test-docs-internal: all-features
    RUSTFLAGS="--cfg docsrs" cargo +nightly test --doc --all-features
    cd {{DOCS_DIR}} && mdbook test -L ../target/debug/deps

# Tests all code in docs
test-docs: test-docs-internal
    RUSTDOCFLAGS="-Dwarnings" cargo ws exec cargo doc --locked --all-features --no-deps --document-private-items

# Runs clippy on all crates
[private]
clippy-inner feature='':
    cargo ws exec cargo {{MSRV}} clippy --locked --all-targets {{feature}} -- -D warnings

# Run clippy on all targets and all sources
[linux]
clippy:
    just clippy-inner --no-default-features
    just clippy-inner
    just clippy-inner --all-features

# Run clippy on.. some things?
[macos]
clippy:
    cargo +nightly clippy --tests --all --exclude libafl_nyx --exclude symcc_runtime --exclude runtime_test

# Run clippy powershell script
[windows]
clippy:
    pwsh {{SCRIPTS_DIR}}/clippy.ps1

# Check the format of all code
check-fmt: (fmt "check")

# Format everything
fmt params="":
    {{SCRIPTS_DIR}}/fmt_all.sh {{params}}

#: We currently only specify minimum rust versions for the default workspace members
msrv:
    cargo hack check --rust-version -p libafl -p libafl_bolts -p libafl_derive -p libafl_cc -p libafl_targets

# Check that all fuzzers are listed below in the justfile
fuzzers-preflight:
    ./scripts/check_tested_fuzzers.sh

# Do nothing (to comment things (out))
nop comment1="" comment2="" comment3="":

test-fuzzer fuzzer_dir:
    {{SCRIPTS_DIR}}/test_fuzzer.sh {{fuzzer_dir}}

test-fuzzers: fuzzers-preflight \
    test-os-specific-fuzzers \
    \
    (nop "Baby" ) \
    (test-fuzzer "./fuzzers/baby/baby_fuzzer_swap_differential") \
    (test-fuzzer "./fuzzers/baby/tutorial") \
    (test-fuzzer "./fuzzers/baby/baby_fuzzer") \
    (nop "./fuzzers/baby/backtrace_baby_fuzzers") \
    (test-fuzzer "./fuzzers/baby/baby_fuzzer_unicode") \
    (test-fuzzer "./fuzzers/baby/baby_fuzzer_minimizing") \
    (test-fuzzer "./fuzzers/baby/backtrace_baby_fuzzers/c_code_with_fork_executor") \
    (test-fuzzer "./fuzzers/baby/backtrace_baby_fuzzers/c_code_with_inprocess_executor") \
    (test-fuzzer "./fuzzers/baby/backtrace_baby_fuzzers/rust_code_with_fork_executor") \
    (test-fuzzer "./fuzzers/baby/backtrace_baby_fuzzers/rust_code_with_inprocess_executor") \
    (test-fuzzer "./fuzzers/baby/backtrace_baby_fuzzers/command_executor") \
    (test-fuzzer "./fuzzers/baby/backtrace_baby_fuzzers/forkserver_executor") \
    (test-fuzzer "./fuzzers/baby/baby_fuzzer_custom_executor") \
    \
    (nop "Binary-only") \
    (test-fuzzer "./fuzzers/binary_only/frida_executable_libpng") \
    (test-fuzzer "./fuzzers/binary_only/frida_libpng") \
    (test-fuzzer "./fuzzers/binary_only/intel_pt_baby_fuzzer") \
    (test-fuzzer "./fuzzers/binary_only/intel_pt_command_executor") \
    (test-fuzzer "./fuzzers/binary_only/tinyinst_simple") \
    \
    (nop "Forkserver") \
    (test-fuzzer "./fuzzers/forkserver/forkserver_simple") \
    (test-fuzzer "./fuzzers/forkserver/forkserver_libafl_cc") \
    (test-fuzzer "./fuzzers/forkserver/fuzzbench_forkserver") \
    (test-fuzzer "./fuzzers/forkserver/fuzzbench_forkserver_cmplog") \
    (test-fuzzer "./fuzzers/forkserver/fuzzbench_forkserver_sand") \
    (test-fuzzer "./fuzzers/forkserver/libafl-fuzz") \
    (test-fuzzer "./fuzzers/forkserver/baby_fuzzer_with_forkexecutor") \
    \
    (nop "Full-system") \
    (test-fuzzer "./fuzzers/full_system/nyx_launcher") \
    (test-fuzzer "./fuzzers/full_system/nyx_libxml2_standalone") \
    (test-fuzzer "./fuzzers/full_system/nyx_libxml2_parallel") \
    \
    (test-fuzzer "./fuzzers/full_system/unicorn") \
    \
    (nop "Structure-aware") \
    (test-fuzzer "./fuzzers/structure_aware/nautilus_sync") \
    (test-fuzzer "./fuzzers/structure_aware/baby_fuzzer_grimoire") \
    (test-fuzzer "./fuzzers/structure_aware/baby_fuzzer_gramatron") \
    (test-fuzzer "./fuzzers/structure_aware/baby_fuzzer_tokens") \
    (test-fuzzer "./fuzzers/structure_aware/baby_fuzzer_multi") \
    (test-fuzzer "./fuzzers/structure_aware/baby_fuzzer_custom_input") \
    (test-fuzzer "./fuzzers/structure_aware/baby_fuzzer_nautilus") \
    (test-fuzzer "./fuzzers/structure_aware/forkserver_simple_nautilus") \
    \
    (nop "In-process") \
    (test-fuzzer "./fuzzers/fuzz_anything/cargo_fuzz") \
    (test-fuzzer "./fuzzers/inprocess/fuzzbench") \
    (test-fuzzer "./fuzzers/inprocess/fuzzbench_text") \
    (test-fuzzer "./fuzzers/inprocess/fuzzbench_ctx") \
    (test-fuzzer "./fuzzers/inprocess/libfuzzer_libmozjpeg") \
    (test-fuzzer "./fuzzers/inprocess/libfuzzer_libpng") \
    (test-fuzzer "./fuzzers/inprocess/libfuzzer_libpng_launcher") \
    (test-fuzzer "./fuzzers/inprocess/libfuzzer_libpng_accounting") \
    (test-fuzzer "./fuzzers/inprocess/libfuzzer_libpng_centralized") \
    (test-fuzzer "./fuzzers/inprocess/libfuzzer_libpng_cmin") \
    (test-fuzzer "./fuzzers/inprocess/libfuzzer_libpng_norestart") \
    (nop "./fuzzers/inprocess/libfuzzer_libpng_tcp_manager") \
    (test-fuzzer "./fuzzers/inprocess/libfuzzer_stb_image_sugar") \
    (test-fuzzer "./fuzzers/inprocess/libfuzzer_stb_image") \
    (nop "./fuzzers/structure_aware/libfuzzer_stb_image_concolic") \
    (nop "./fuzzers/inprocess/sqlite_centralized_multi_machine") \
    \
    (nop "Fuzz Anything") \
    (test-fuzzer "./fuzzers/fuzz_anything/push_harness") \
    (test-fuzzer "./fuzzers/fuzz_anything/push_stage_harness") \
    (test-fuzzer "./fuzzers/fuzz_anything/libafl_atheris") \
    (test-fuzzer "./fuzzers/fuzz_anything/baby_no_std") \
    (test-fuzzer "./fuzzers/fuzz_anything/baby_fuzzer_wasm") \

# Windows-specific cmplog test
[windows]
test-fuzzers-gdiplus-cmplog:
    cd {{FUZZERS_DIR}}/binary_only/frida_windows_gdiplus/ && just test_cmplog


# Fuzzers specific to linux
[linux]
test-os-specific-fuzzers: test-python-fuzzer \
    (nop "Binary-only") \
    (test-fuzzer "./fuzzers/binary_only/fuzzbench_fork_qemu") \
    (test-fuzzer "./fuzzers/binary_only/fuzzbench_qemu") \
    \
    (nop "Full-system") \
    (test-fuzzer "./fuzzers/full_system/qemu_baremetal") \
    (test-fuzzer "./fuzzers/full_system/qemu_linux_kernel") \
    (test-fuzzer "./fuzzers/full_system/qemu_linux_process") \
    \
    (nop "Binary only") \
    (test-fuzzer "./fuzzers/binary_only/qemu_cmin") \
    (test-fuzzer "./fuzzers/binary_only/qemu_coverage") \
    (test-fuzzer "./fuzzers/binary_only/qemu_launcher") \

# Fuzzers specific to MacOS
[macos]
test-os-specific-fuzzers:

# Fuzzers specific to Windows
[windows]
test-os-specific-fuzzers: \
    (test-fuzzer "./fuzzers/inprocess/libfuzzer_windows_asan") \
    (test-fuzzer "./fuzzers/binary_only/frida_windows_gdiplus") \
    (test-fuzzer "fuzzers/binary_only/frida_libpng/") \
    (test-fuzzer "fuzzers/binary_only/tinyinst_simple/") \
    test-fuzzers-gdiplus-cmplog

# Tests the python fuzzer
[linux]
test-python-fuzzer:
    sh -c ". {{ROOT_DIR}}/bindings/pylibafl/.env/bin/activate && cd {{FUZZERS_DIR}}/binary_only/python_qemu/ && python3 fuzzer.py 2>&1 | grepy 'Bye'"

# Builds the python bindings
build-python:
    sh -C "cd {{ROOT_DIR}}/bindings/pylibafl && python3 -m venv .env && . .env/bin/activate && pip install --upgrade --force-reinstall . && ./test.sh"

# Task to run clippy, rustfmt, and audit on all crates
cleanliness: clippy check-fmt

build-librasan:
    just \
        -f {{FUZZERS_DIR}}/libafl_qemu/librasan/Justfile \
        build_everything_dev \
        build_x86_64_release

test-librasan:
    just \
        -f {{FUZZERS_DIR}}/libafl_qemu/librasan/Justfile \
        test_everything

# Publish all crates
[unix]
publish:
    cd {{ROOT_DIR}} && cargo ws publish --publish-as-is --no-remove-dev-deps --token $CRATES_IO_TOKEN

[unix]
autofix:
    {{SCRIPTS_DIR}}/autofix.sh

clean:
    cargo clean
    find {{FUZZERS_DIR}} -d -name 'target'  -exec rm -r {} \;

docker:
    docker build -t libafl {{ROOT_DIR}}

# Runs hellcheck on the scripts folder
[unix]
shellcheck:
    shellcheck {{SCRIPTS_DIR}}/*.sh

# Builds libafl for Android
build-android:
    cd {{LIBAFL_DIR}} && PYO3_CROSS_PYTHON_VERSION=$(python3 -c "print('{}.{}'.format(__import__('sys').version_info.major, __import__('sys').version_info.minor))") cargo ndk -t arm64-v8a build --release

# Builds libafl for iOS
build-ios:
    PYO3_CROSS_PYTHON_VERSION=$(python3 -c "print('{}.{}'.format(__import__('sys').version_info.major, __import__('sys').version_info.minor))") cargo build --target aarch64-apple-ios && cd {{ROOT_DIR}}/libafl_frida && cargo build --target aarch64-apple-ios

# Increase mem limit for macos
[macos]
increase-mem-limits:
    {{SCRIPTS_DIR}}/shmem_limits_macos.sh

# Run Smoketest for the libafl concolic executor
[linux]
concolic-smoke-test:
    {{ROOT_DIR}}/libafl_concolic/test/smoke_test.sh
