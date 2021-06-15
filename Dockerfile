# syntax=docker/dockerfile:1.2
FROM rust:bullseye AS libafl
LABEL "maintainer"="afl++ team <afl@aflplus.plus>"
LABEL "about"="LibAFL Docker image"

# Install clang 11
RUN apt update && apt install -y build-essential git wget clang-11 clang-tools-11 libc++-11-dev libc++abi-11-dev

RUN cargo install sccache

ENV HOME=/root
ENV SCCACHE_CACHE_SIZE="1G"
ENV SCCACHE_DIR=$HOME/.cache/sccache
ENV RUSTC_WRAPPER="/usr/local/cargo/bin/sccache"
ENV IS_DOCKER="1"
RUN sh -c 'echo set encoding=utf-8 > /root/.vimrc' \
    echo "export PS1='"'[LibAFL \h] \w$(__git_ps1) \$ '"'" >> ~/.bashrc

RUN --mount=type=cache,target=/root/.cache/sccache rustup component add rustfmt clippy

# Copy a dummy.rs and Cargo.toml first, so that dependencies are cached
WORKDIR /libafl
COPY Cargo.toml README.md ./

COPY libafl_derive/Cargo.toml libafl_derive/Cargo.toml
COPY scripts/dummy.rs libafl_derive/src/lib.rs

COPY libafl/Cargo.toml libafl/build.rs libafl/
COPY libafl/benches libafl/benches
COPY libafl/examples libafl/examples
COPY scripts/dummy.rs libafl/src/lib.rs

COPY libafl_frida/Cargo.toml libafl_frida/build.rs libafl_frida/
COPY scripts/dummy.rs libafl_frida/src/lib.rs
COPY libafl_frida/src/gettls.c libafl_frida/src/gettls.c

COPY libafl_cc/Cargo.toml libafl_cc/Cargo.toml
COPY scripts/dummy.rs libafl_cc/src/lib.rs

COPY libafl_targets/Cargo.toml libafl_targets/build.rs libafl_targets/
COPY libafl_targets/src libafl_targets/src
COPY scripts/dummy.rs libafl_targets/src/lib.rs

COPY libafl_tests/Cargo.toml libafl_tests/build.rs libafl_tests/
COPY scripts/dummy.rs libafl_tests/src/lib.rs

RUN --mount=type=cache,target=/root/.cache/sccache cargo build && cargo build --release

COPY scripts scripts
COPY docs docs

# Pre-build dependencies for a few common fuzzers

# Dep chain:
# libafl_cc (independent)
# libafl_derive -> libafl
# libafl_tests -> libafl
# libafl -> libafl_targets
# libafl_targets -> libafl_frida

# Build once without source
COPY libafl_cc/src libafl_cc/src
RUN touch libafl_cc/src/lib.rs
COPY libafl_derive/src libafl_derive/src
RUN touch libafl_derive/src/lib.rs
COPY libafl_tests/src libafl_tests/src
RUN touch libafl_tests/src/lib.rs
COPY libafl/src libafl/src
RUN touch libafl/src/lib.rs
COPY libafl_targets/src libafl_targets/src
RUN touch libafl_targets/src/lib.rs
COPY libafl_frida/src libafl_frida/src
RUN touch libafl_frida/src/lib.rs
RUN --mount=type=cache,target=/root/.cache/sccache cargo build && cargo build --release

# Copy fuzzers over
COPY fuzzers fuzzers

RUN --mount=type=cache,target=/root/.cache/sccache ./scripts/build_all_fuzzers.sh

ENTRYPOINT [ "/bin/bash" ]
