# syntax=docker/dockerfile:1.2
FROM rust:1.87.0 AS libafl
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

RUN rustup component add rustfmt clippy

RUN rustup target add armv7-unknown-linux-gnueabi
RUN rustup target add aarch64-unknown-linux-gnu
RUN rustup target add i686-unknown-linux-gnu
RUN rustup target add powerpc-unknown-linux-gnu

# Install clang 18, common build tools
ENV LLVM_VERSION=18
ENV LLVM_CONFIG=llvm-config-${LLVM_VERSION}
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
    gcc-riscv64-linux-gnu \
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
    ca-certificates \
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
ENV QEMU_VER=10.0.0
RUN wget https://download.qemu.org/qemu-${QEMU_VER}.tar.xz && \
    tar xvJf qemu-${QEMU_VER}.tar.xz && \
    cd /root/qemu-${QEMU_VER} && \
   ./configure --target-list="\
      arm-linux-user,\
      aarch64-linux-user,\
      i386-linux-user,\
      ppc-linux-user,\
      mips-linux-user,\
      x86_64-linux-user,\
      arm-softmmu,\
      aarch64-softmmu,\
      i386-softmmu,\
      ppc-softmmu,\
      mips-softmmu,\
      x86_64-softmmu" && \
    make -j && \
    make install && \
    cd /root && \
    rm -rf qemu-${QEMU_VER}

ENTRYPOINT [ "/bin/bash", "-c" ]
CMD ["/bin/bash"]
