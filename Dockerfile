#
# This Dockerfile for LibAFL uses rust:bullseye as base.
#

FROM rust:bullseye AS libafl
LABEL "maintainer"="afl++ team <afl@aflplus.plus>"
LABEL "about"="AFLplusplus docker image"

ARG DEBIAN_FRONTEND=noninteractive

RUN sh -c 'echo set encoding=utf-8 > /root/.vimrc' \
    echo "export PS1='"'[LibAFL \h] \w$(__git_ps1) \$ '"'" >> ~/.bashrc
ENV IS_DOCKER="1"

# Copy a dummy.rs and Cargo.toml first, so that dependencies are cached
WORKDIR /libafl
COPY Cargo.toml Cargo.toml
COPY README.md README.md

COPY libafl_derive/Cargo.toml libafl_derive/Cargo.toml
COPY scripts/dummy.rs libafl_derive/src/lib.rs

COPY libafl/Cargo.toml libafl/Cargo.toml
COPY libafl/build.rs libafl/build.rs
COPY libafl/benches libafl/benches
COPY libafl/examples libafl/examples
COPY scripts/dummy.rs libafl/src/lib.rs

COPY libafl_frida/Cargo.toml libafl_frida/Cargo.toml
COPY libafl_frida/build.rs libafl_frida/build.rs
COPY scripts/dummy.rs libafl_frida/src/lib.rs

COPY libafl_cc/Cargo.toml libafl_cc/Cargo.toml
COPY scripts/dummy.rs libafl_cc/src/lib.rs

COPY libafl_targets/Cargo.toml libafl_targets/Cargo.toml
COPY libafl_targets/build.rs libafl_targets/build.rs
COPY scripts/dummy.rs libafl_targets/src/lib.rs

COPY libafl_tests/Cargo.toml libafl_tests/Cargo.toml
COPY libafl_tests/build.rs libafl_tests/build.rs
COPY scripts/dummy.rs libafl_tests/src/lib.rs

COPY docs docs

RUN cargo build && cargo build --release

# Pre-build dependencies for a few common fuzzers
COPY fuzzers/baby_fuzzer/Cargo.toml fuzzers/baby_fuzzer/Cargo.toml
COPY fuzzers/baby_fuzzer/README.md fuzzers/baby_fuzzer/README.md 
COPY scripts/dummy.rs fuzzers/baby_fuzzer/src/main.rs
WORKDIR /libafl/fuzzers/baby_fuzzer
RUN cargo build && cargo build --release
WORKDIR /libafl

COPY fuzzers/forkserver_simple/Cargo.toml fuzzers/forkserver_simple/Cargo.toml
COPY fuzzers/forkserver_simple/README.md fuzzers/forkserver_simple/README.md 
COPY scripts/dummy.rs fuzzers/forkserver_simple/src/main.rs
WORKDIR /libafl/fuzzers/forkserver_simple
RUN cargo build && cargo build --release
WORKDIR /libafl

COPY fuzzers/frida_libpng/Cargo.toml fuzzers/frida_libpng/Cargo.toml
COPY fuzzers/frida_libpng/README.md fuzzers/frida_libpng/README.md 
COPY fuzzers/frida_libpng/build.rs fuzzers/frida_libpng/build.rs 
COPY scripts/dummy.rs fuzzers/frida_libpng/src/main.rs
WORKDIR /libafl/fuzzers/frida_libpng
RUN cargo build && cargo build --release
WORKDIR /libafl

COPY fuzzers/generic_inmemory/Cargo.toml fuzzers/generic_inmemory/Cargo.toml
COPY fuzzers/generic_inmemory/README.md fuzzers/generic_inmemory/README.md 
COPY scripts/dummy.rs fuzzers/generic_inmemory/src/main.rs
WORKDIR /libafl/fuzzers/generic_inmemory
RUN cargo build && cargo build --release
WORKDIR /libafl

# Dep chain:
# libafl_cc (independent)
# libafl_derive -> libafl
# libafl_tests -> libafl
# libafl -> libafl_targets
# libafl_targets -> libafl_frida

# Build once without source
COPY libafl_cc/src libafl_cc/src
RUN touch libafl_cc/src/lib.rs && cargo build && cargo build --release

COPY libafl_derive/src libafl_derive/src
RUN touch libafl_derive/src/lib.rs && cargo build && cargo build --release

COPY libafl_tests/src libafl_tests/src
RUN touch libafl_tests/src/lib.rs && cargo build && cargo build --release

COPY libafl/src libafl/src
RUN touch libafl/src/lib.rs && cargo build && cargo build --release

COPY libafl_targets/src libafl_targets/src
RUN touch libafl_targets/src/lib.rs && cargo build && cargo build --release

COPY libafl_frida/src libafl_frida/src
RUN touch libafl_frida/src/lib.rs && cargo build && cargo build --release

# Copy fuzzers over
COPY fuzzers/baby_fuzzer/src fuzzers/baby_fuzzer/src/src
RUN touch fuzzers/baby_fuzzer/src/main.rs
COPY fuzzers/forkserver_simple/corpus fuzzers/forkserver_simple/corpus
COPY fuzzers/forkserver_simple/src fuzzers/forkserver_simple/src
RUN touch fuzzers/forkserver_simple/src/main.rs
COPY fuzzers/frida_libpng/src fuzzers/frida_libpng/src
COPY fuzzers/frida_libpng/harness.cc fuzzers/frida_libpng/harness.cc
RUN touch fuzzers/frida_libpng/src/main.rs
COPY fuzzers/generic_inmemory/src fuzzers/generic_inmemory/src
COPY fuzzers/generic_inmemory/fuzz.c fuzzers/generic_inmemory/fuzz.c
RUN touch fuzzers/frida_libpng/src/main.rs
COPY fuzzers/libfuzzer_libmozjpeg fuzzers/libfuzzer_libmozjpg
COPY fuzzers/libfuzzer_libpng fuzzers/libfuzzer_libpng
COPY fuzzers/libfuzzer_libpng_launcher fuzzers/libfuzzer_libpng_launcher
COPY fuzzers/libfuzzer_reachability fuzzers/libfuzzer_reachability
COPY fuzzers/libfuzzer_stb_image fuzzers/libfuzzer_stb_image

#RUN ./scripts/build_all_fuzzers.sh


ENTRYPOINT [ "/bin/bash" ]
