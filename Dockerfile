# syntax=docker/dockerfile:1.2
FROM rust:1.76.0 AS libafl
LABEL "maintainer"="afl++ team <afl@aflplus.plus>"
LABEL "about"="LibAFL Docker image"

# install sccache to cache subsequent builds of dependencies
RUN cargo install --locked sccache

ENV HOME=/root
ENV SCCACHE_CACHE_SIZE="1G"
ENV SCCACHE_DIR=$HOME/.cache/sccache
ENV RUSTC_WRAPPER="/usr/local/cargo/bin/sccache"
ENV IS_DOCKER="1"
RUN sh -c 'echo set encoding=utf-8 > /root/.vimrc' \
    echo "export PS1='"'[LibAFL \h] \w$(__git_ps1) \$ '"'" >> ~/.bashrc && \
    mkdir ~/.cargo && \
    echo "[build]\nrustc-wrapper = \"${RUSTC_WRAPPER}\"" >> ~/.cargo/config

RUN rustup component add rustfmt clippy
RUN rustup default nightly

# Install clang 18, common build tools
ENV LLVM_VERSION=18
RUN apt update && apt install -y build-essential gdb git wget python3-venv ninja-build lsb-release software-properties-common gnupg cmake
# Workaround until https://github.com/llvm/llvm-project/issues/62475 is resolved
RUN set -ex &&\
    echo "deb http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-${LLVM_VERSION} main" > /etc/apt/sources.list.d/apt.llvm.org.list &&\
    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key |  tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc &&\
    apt update &&\
    apt-get install -y clang-${LLVM_VERSION} lldb-${LLVM_VERSION} lld-${LLVM_VERSION} clangd-${LLVM_VERSION} clang-tidy-${LLVM_VERSION} clang-format-${LLVM_VERSION} clang-tools-${LLVM_VERSION} llvm-${LLVM_VERSION}-dev lld-${LLVM_VERSION} lldb-${LLVM_VERSION} llvm-${LLVM_VERSION}-tools libomp-${LLVM_VERSION}-dev libc++-${LLVM_VERSION}-dev libc++abi-${LLVM_VERSION}-dev libclang-common-${LLVM_VERSION}-dev libclang-${LLVM_VERSION}-dev libclang-cpp${LLVM_VERSION}-dev libunwind-${LLVM_VERSION}-dev libclang-rt-${LLVM_VERSION}-dev libpolly-${LLVM_VERSION}-dev

# Copy a dummy.rs and Cargo.toml first, so that dependencies are cached
WORKDIR /libafl
COPY Cargo.toml README.md ./

COPY libafl_derive/Cargo.toml libafl_derive/Cargo.toml
COPY scripts/dummy.rs libafl_derive/src/lib.rs

COPY libafl/Cargo.toml libafl/build.rs libafl/README.md libafl/
COPY scripts/dummy.rs libafl/src/lib.rs

COPY libafl_bolts/Cargo.toml libafl_bolts/build.rs libafl_bolts/README.md libafl_bolts/
COPY libafl_bolts/examples libafl_bolts/examples
COPY scripts/dummy.rs libafl_bolts/src/lib.rs

COPY libafl_frida/Cargo.toml libafl_frida/build.rs libafl_frida/
COPY scripts/dummy.rs libafl_frida/src/lib.rs
COPY libafl_frida/src/gettls.c libafl_frida/src/gettls.c

COPY libafl_qemu/Cargo.toml libafl_qemu/build.rs libafl_qemu/build_linux.rs libafl_qemu/
COPY scripts/dummy.rs libafl_qemu/src/lib.rs

COPY libafl_qemu/libafl_qemu_build/Cargo.toml libafl_qemu/libafl_qemu_build/
COPY scripts/dummy.rs libafl_qemu/libafl_qemu_build/src/lib.rs

COPY libafl_qemu/libafl_qemu_sys/Cargo.toml libafl_qemu/libafl_qemu_sys/build.rs libafl_qemu/libafl_qemu_sys/build_linux.rs libafl_qemu/libafl_qemu_sys/
COPY scripts/dummy.rs libafl_qemu/libafl_qemu_sys/src/lib.rs

COPY libafl_sugar/Cargo.toml libafl_sugar/
COPY scripts/dummy.rs libafl_sugar/src/lib.rs

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

COPY libafl_nyx/Cargo.toml libafl_nyx/build.rs libafl_nyx/
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
RUN touch libafl_qemu/src/lib.rs
COPY libafl_qemu/src libafl_qemu/src
RUN touch libafl_frida/src/lib.rs
COPY libafl_concolic/symcc_libafl libafl_concolic/symcc_libafl
COPY libafl_concolic/symcc_runtime libafl_concolic/symcc_runtime
COPY libafl_concolic/test libafl_concolic/test
COPY libafl_nyx/src libafl_nyx/src
RUN touch libafl_nyx/src/lib.rs
COPY libafl_libfuzzer/src libafl_libfuzzer/src
COPY libafl_libfuzzer/libafl_libfuzzer_runtime libafl_libfuzzer/libafl_libfuzzer_runtime
COPY libafl_libfuzzer/build.rs libafl_libfuzzer/build.rs
RUN touch libafl_libfuzzer/src/lib.rs
RUN cargo build && cargo build --release

# Copy fuzzers over
COPY fuzzers fuzzers

# RUN ./scripts/test_all_fuzzers.sh --no-fmt

ENTRYPOINT [ "/bin/bash", "-c" ]
CMD ["/bin/bash"]
