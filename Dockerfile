# syntax=docker/dockerfile:1.2
FROM rust:1.76.0 AS libafl
LABEL "maintainer"="afl++ team <afl@aflplus.plus>"
LABEL "about"="LibAFL Docker image"

# Install cargo-binstall to download the sccache build
RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
# install sccache to cache subsequent builds of dependencies
RUN cargo binstall --no-confirm sccache

ENV HOME=/root
ENV SCCACHE_CACHE_SIZE="1G"
ENV SCCACHE_DIR=$HOME/.cache/sccache
ENV RUSTC_WRAPPER="/usr/local/cargo/bin/sccache"
ENV IS_DOCKER="1"
RUN sh -c 'echo set encoding=utf-8 > /root/.vimrc' \
    echo "export PS1='"'[LibAFL \h] \w$(__git_ps1) \$ '"'" >> ~/.bashrc && \
    mkdir ~/.cargo && \
    echo "[build]\nrustc-wrapper = \"${RUSTC_WRAPPER}\"" >> ~/.cargo/config

RUN rustup default nightly
RUN rustup component add rustfmt clippy

# Install clang 18, common build tools
ENV LLVM_VERSION=18
RUN apt update && apt install -y build-essential gdb git wget python3-venv ninja-build lsb-release software-properties-common gnupg cmake
RUN set -ex &&\
    wget https://apt.llvm.org/llvm.sh &&\
    chmod +x llvm.sh &&\
    ./llvm.sh ${LLVM_VERSION}


# Copy a dummy.rs and Cargo.toml first, so that dependencies are cached
WORKDIR /libafl
COPY Cargo.toml README.md ./

COPY libafl_derive/Cargo.toml libafl_derive/Cargo.toml
COPY scripts/dummy.rs libafl_derive/src/lib.rs

COPY libafl/Cargo.toml libafl/build.rs libafl/README.md libafl/
COPY scripts/dummy.rs libafl/src/lib.rs

# Set up LLVM aliases
COPY scripts/createAliases.sh libafl/
RUN bash libafl/createAliases.sh ${LLVM_VERSION}

COPY libafl_bolts/Cargo.toml libafl_bolts/build.rs libafl_bolts/README.md libafl_bolts/
COPY libafl_bolts/examples libafl_bolts/examples
COPY scripts/dummy.rs libafl_bolts/src/lib.rs

COPY libafl_frida/Cargo.toml libafl_frida/build.rs libafl_frida/
COPY scripts/dummy.rs libafl_frida/src/lib.rs
COPY libafl_frida/src/gettls.c libafl_frida/src/gettls.c

COPY libafl_intelpt/Cargo.toml libafl_intelpt/README.md libafl_intelpt/
COPY scripts/dummy.rs libafl_intelpt/src/lib.rs

COPY libafl_qemu/Cargo.toml libafl_qemu/build.rs libafl_qemu/build_linux.rs libafl_qemu/
COPY scripts/dummy.rs libafl_qemu/src/lib.rs

COPY libafl_qemu/libafl_qemu_build/Cargo.toml libafl_qemu/libafl_qemu_build/
COPY scripts/dummy.rs libafl_qemu/libafl_qemu_build/src/lib.rs

COPY libafl_qemu/libafl_qemu_sys/Cargo.toml libafl_qemu/libafl_qemu_sys/build.rs libafl_qemu/libafl_qemu_sys/build_linux.rs libafl_qemu/libafl_qemu_sys/
COPY scripts/dummy.rs libafl_qemu/libafl_qemu_sys/src/lib.rs

COPY libafl_sugar/Cargo.toml libafl_sugar/
COPY scripts/dummy.rs libafl_sugar/src/lib.rs

COPY bindings/pylibafl/Cargo.toml bindings/pylibafl/Cargo.toml
COPY bindings/pylibafl/src bindings/pylibafl/src

COPY libafl_cc/Cargo.toml libafl_cc/Cargo.toml
COPY libafl_cc/build.rs libafl_cc/build.rs
COPY libafl_cc/src libafl_cc/src
COPY scripts/dummy.rs libafl_cc/src/lib.rs

COPY libafl_targets/Cargo.toml libafl_targets/build.rs libafl_targets/
COPY libafl_targets/src libafl_targets/src
COPY scripts/dummy.rs libafl_targets/src/lib.rs

COPY libafl_concolic/test/dump_constraints/Cargo.toml libafl_concolic/test/dump_constraints/
COPY scripts/dummy.rs libafl_concolic/test/dump_constraints/src/lib.rs

COPY libafl_concolic/test/runtime_test/Cargo.toml libafl_concolic/test/runtime_test/
COPY scripts/dummy.rs libafl_concolic/test/runtime_test/src/lib.rs

COPY libafl_concolic/symcc_runtime/Cargo.toml libafl_concolic/symcc_runtime/build.rs libafl_concolic/symcc_runtime/
COPY scripts/dummy.rs libafl_concolic/symcc_runtime/src/lib.rs

COPY libafl_concolic/symcc_libafl/Cargo.toml libafl_concolic/symcc_libafl/
COPY scripts/dummy.rs libafl_concolic/symcc_libafl/src/lib.rs

COPY libafl_nyx/Cargo.toml libafl_nyx/build.rs libafl_nyx/build_nyx_support.sh libafl_nyx/
COPY scripts/dummy.rs libafl_nyx/src/lib.rs

COPY libafl_tinyinst/Cargo.toml libafl_tinyinst/
COPY scripts/dummy.rs libafl_tinyinst/src/lib.rs

# avoid pulling in the runtime, as this is quite an expensive build, until later
COPY libafl_libfuzzer/Cargo.toml libafl_libfuzzer/
COPY scripts/dummy.rs libafl_libfuzzer/src/lib.rs

COPY utils utils

RUN cargo build && cargo build --release

COPY scripts scripts
COPY docs docs

# Pre-build dependencies for a few common fuzzers

# Dep chain:
# libafl_cc (independent)
# libafl_derive -> libafl
# libafl -> libafl_targets
# libafl_targets -> libafl_frida

# Build once without source
COPY libafl_cc/src libafl_cc/src
RUN touch libafl_cc/src/lib.rs
COPY libafl_derive/src libafl_derive/src
RUN touch libafl_derive/src/lib.rs
COPY libafl_bolts/src libafl_bolts/src
RUN touch libafl_bolts/src/lib.rs
COPY libafl/src libafl/src
RUN touch libafl/src/lib.rs
COPY libafl_targets/src libafl_targets/src
RUN touch libafl_targets/src/lib.rs
COPY libafl_frida/src libafl_frida/src
RUN touch libafl_qemu/libafl_qemu_build/src/lib.rs
COPY libafl_qemu/libafl_qemu_build/src libafl_qemu/libafl_qemu_build/src
RUN touch libafl_qemu/libafl_qemu_sys/src/lib.rs
COPY libafl_qemu/libafl_qemu_sys/src libafl_qemu/libafl_qemu_sys/src
COPY libafl_qemu/runtime libafl_qemu/runtime
COPY libafl_qemu/libqasan libafl_qemu/libqasan
RUN touch libafl_qemu/src/lib.rs
COPY libafl_qemu/src libafl_qemu/src
RUN touch libafl_frida/src/lib.rs
COPY libafl_concolic/symcc_libafl libafl_concolic/symcc_libafl
COPY libafl_concolic/symcc_runtime libafl_concolic/symcc_runtime
COPY libafl_concolic/test libafl_concolic/test
COPY libafl_nyx/src libafl_nyx/src
RUN touch libafl_nyx/src/lib.rs
COPY libafl_libfuzzer_runtime libafl_libfuzzer_runtime
COPY libafl_libfuzzer/src libafl_libfuzzer/src
COPY libafl_libfuzzer/runtime libafl_libfuzzer/runtime
COPY libafl_libfuzzer/build.rs libafl_libfuzzer/build.rs
RUN touch libafl_libfuzzer/src/lib.rs
COPY libafl_intelpt/src libafl_intelpt/src
RUN touch libafl_intelpt/src/lib.rs
RUN cargo build && cargo build --release

# Copy fuzzers over
COPY fuzzers fuzzers

# RUN ./scripts/test_fuzzer.sh --no-fmt

ENTRYPOINT [ "/bin/bash", "-c" ]
CMD ["/bin/bash"]
