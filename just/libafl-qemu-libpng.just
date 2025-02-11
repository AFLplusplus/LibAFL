import "libafl-qemu.just"

# Useful rules to build libpng for multiple architecture.

CROSS_CC := env("CROSS_CC", "x86_64-linux-gnu-gcc")
CROSS_CXX := env("CROSS_CXX", "x86_64-linux-gnu-g++")
CROSS_CFLAGS := env("CROSS_CFLAGS", "")

DEFAULT_ARCH := env("LIBPNG_ARCH", "x86_64")
OPTIMIZATIONS := env("LIBPNG_OPTIMIZATIONS", "yes")

DEPS_DIR := TARGET_DIR / "deps"

[unix]
target_dir:
    mkdir -p {{ TARGET_DIR }}

[unix]
deps_dir:
    mkdir -p {{ DEPS_DIR }}

[unix]
arch_dir arch:
    mkdir -p {{ arch }}

[unix]
zlib_wget: deps_dir
    #!/bin/bash

    wget \
        -O "{{ DEPS_DIR }}/zlib-1.2.13.tar.gz" \
        https://zlib.net/fossils/zlib-1.2.13.tar.gz

    tar \
        zxvf {{ DEPS_DIR }}/zlib-1.2.13.tar.gz \
        -C {{ DEPS_DIR }}

[unix]
zlib: zlib_wget
    #!/bin/bash

    rm -rf {{ TARGET_DIR }}/build-zlib/

    mkdir {{ TARGET_DIR }}/build-zlib/

    cd {{ TARGET_DIR }}/build-zlib/ && \
        CC={{ CROSS_CC }} \
        CFLAGS={{ CROSS_CFLAGS }} \
        {{ DEPS_DIR }}/zlib-1.2.13/configure \
            --prefix=./zlib

    make -j install

[unix]
libpng_wget: deps_dir
    wget \
        -O "{{ DEPS_DIR }}/v1.6.37.tar.gz" \
        https://github.com/glennrp/libpng/archive/refs/tags/v1.6.37.tar.gz

    tar \
        -xvf "{{ DEPS_DIR }}/v1.6.37.tar.gz" \
        -C {{ DEPS_DIR }}

[unix]
libpng arch=DEFAULT_ARCH: (arch_dir arch) zlib libpng_wget
    rm -rf {{ TARGET_DIR }}/build-png/

    mkdir {{TARGET_DIR}}/build-png/

    cd {{TARGET_DIR}}/build-png/ && \
        CC={{ CROSS_CC }} \
        CFLAGS="{{ CROSS_CXX }} -I"{{ TARGET_DIR }}/build-zlib/zlib/lib"" \
        LDFLAGS=-L"{{ TARGET_DIR }}/build-zlib/zlib/lib" \
        {{ DEPS_DIR }}/libpng-1.6.37/configure \
            --enable-shared=no \
            --with-pic=yes \
            --enable-hardware-optimizations={{OPTIMIZATIONS}} \
            --host={{ arch }} \

    make -j