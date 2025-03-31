# syntax=docker/dockerfile:1.2
FROM rust:1.85.0 AS libafl
LABEL "maintainer"="afl++ team <afl@aflplus.plus>"
LABEL "about"="LibAFL Docker image"

# Install cargo-binstall
RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash

# We now use just to build things rather than cargo-make
RUN cargo binstall --no-confirm just
# Nexttest allows us to run tests which panic in an environment where we can't unwind
RUN cargo binstall --no-confirm cargo-nextest
# Cargo fuzz is useful for fuzz testing our implementations
RUN cargo binstall -y cargo-fuzz
# Taplo allows us to format toml files
RUN cargo binstall -y taplo-cli

ENV HOME=/root
ENV IS_DOCKER="1"
RUN sh -c 'echo set encoding=utf-8 > /root/.vimrc' \
  echo "export PS1='"'[LibAFL \h] \w$(__git_ps1) \$ '"'" >> ~/.bashrc && \
  mkdir ~/.cargo && \
  echo "[build]\nrustc-wrapper = \"${RUSTC_WRAPPER}\"" >> ~/.cargo/config

RUN rustup default nightly
RUN rustup component add rustfmt clippy

RUN rustup target add armv7-unknown-linux-gnueabi
RUN rustup target add aarch64-unknown-linux-gnu
RUN rustup target add i686-unknown-linux-gnu
RUN rustup target add powerpc-unknown-linux-gnu

# Install clang 18, common build tools
ENV LLVM_VERSION=18
RUN dpkg --add-architecture i386
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    cmake \
    curl \
    g++-aarch64-linux-gnu \
    g++-arm-linux-gnueabi \
    g++-i686-linux-gnu \
    g++-mipsel-linux-gnu \
    g++-powerpc-linux-gnu \
    gcc-aarch64-linux-gnu \
    gcc-arm-linux-gnueabi \
    gcc-i686-linux-gnu \
    gcc-mipsel-linux-gnu \
    gcc-powerpc-linux-gnu \
    gdb \
    gdb-multiarch \
    git \
    gnupg \
    less \
    libc6-dev:i386 \
    libclang-dev \
    libgcc-12-dev:i386 \
    libglib2.0-dev \
    lsb-release \
    ninja-build \
    python3 \
    python3-pip \
    python3-venv \
    software-properties-common \
    wget
RUN set -ex &&\
  wget https://apt.llvm.org/llvm.sh &&\
  chmod +x llvm.sh &&\
  ./llvm.sh ${LLVM_VERSION}

RUN apt-get update && \
  apt-get install -y \
  clang-format-${LLVM_VERSION}

# Install a modern version of QEMU
WORKDIR /root
ENV QEMU_VER=9.2.1
RUN wget https://download.qemu.org/qemu-${QEMU_VER}.tar.xz && \
    tar xvJf qemu-${QEMU_VER}.tar.xz && \
    cd /root/qemu-${QEMU_VER} && \
   ./configure --target-list="\
      arm-linux-user,\
      aarch64-linux-user,\
      i386-linux-user,\
      ppc-linux-user,\
      mips-linux-user,\
      arm-softmmu,\
      aarch64-softmmu,\
      i386-softmmu,\
      ppc-softmmu,\
      mips-softmmu" && \
    make -j && \
    make install && \
    cd /root && \
    rm -rf qemu-${QEMU_VER}

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

COPY libafl_unicorn/Cargo.toml libafl_unicorn/
COPY scripts/dummy.rs libafl_unicorn/src/lib.rs

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
COPY libafl_unicorn/src libafl_unicorn/src
RUN touch libafl_unicorn/src/lib.rs
RUN cargo build && cargo build --release

# Copy fuzzers over
COPY fuzzers fuzzers

# RUN ./scripts/test_fuzzer.sh --no-fmt

ENTRYPOINT [ "/bin/bash", "-c" ]
CMD ["/bin/bash"]
