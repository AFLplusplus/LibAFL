import "libafl-qemu.just"

# Useful rules to build libpng for multiple architecture.

ARCH := env("ARCH", "x86_64")
OPTIMIZATIONS := env("OPTIMIZATIONS", if ARCH == "ppc" { "no" } else { "yes" })

DEPS_DIR := TARGET_DIR / "deps"

DOTENV := source_directory() / "envs" / ".env." + ARCH

[unix]
target_dir:
    mkdir -p {{ TARGET_DIR }}

[unix]
deps_dir:
    mkdir -p {{ DEPS_DIR }}

[unix]
arch_dir:
    mkdir -p {{ ARCH }}

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

    source {{ DOTENV }}

    rm -rf {{ TARGET_DIR }}/build-zlib/

    mkdir {{ TARGET_DIR }}/build-zlib/

    cd {{ TARGET_DIR }}/build-zlib/ && \
        CC=$CROSS_CC \
        CFLAGS=$CROSS_CFLAGS \
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
libpng: arch_dir zlib libpng_wget
    #!/bin/bash

    source {{ DOTENV }}

    rm -rf {{ TARGET_DIR }}/build-png/

    mkdir {{TARGET_DIR}}/build-png/

    cd {{ TARGET_DIR }}/build-png/ && \
        CC=$CROSS_CC \
        CFLAGS="$CROSS_CFLAGS -I"{{ TARGET_DIR }}/build-zlib/zlib/lib"" \
        LDFLAGS=-L"{{ TARGET_DIR }}/build-zlib/zlib/lib" \
        {{ DEPS_DIR }}/libpng-1.6.37/configure \
            --enable-shared=no \
            --with-pic=yes \
            --enable-hardware-optimizations={{ OPTIMIZATIONS }} \
            --host={{ ARCH }}

    make -j -C {{ TARGET_DIR }}/build-png/
