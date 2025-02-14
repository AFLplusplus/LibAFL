import "libafl-cc.just"

OPTIMIZATIONS := env("OPTIMIZATIONS", "yes")

LIBPNG_ROOT :=  DEPS_DIR / "libpng-1.6.37"
LIBPNG_BUILD := TARGET_DIR / "build-png"
LIBPNG_INCLUDE := LIBPNG_ROOT

ZLIB_ROOT := DEPS_DIR / "zlib-1.2.13"
ZLIB_BUILD := TARGET_DIR / "build-zlib"
ZLIB_INCLUDE := ZLIB_BUILD / "zlib" / "include"
ZLIB_LIB := ZLIB_BUILD / "zlib" / "lib"

DEPS_DIR := TARGET_DIR / "deps"

[unix]
target_dir:
    mkdir -p {{ TARGET_DIR }}

[unix]
deps_dir:
    mkdir -p {{ DEPS_DIR }}

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

    rm -rf {{ ZLIB_BUILD }}
    mkdir {{ ZLIB_BUILD }}

    cd {{ ZLIB_BUILD }} && \
        CC={{LIBAFL_CC}} \
        {{ ZLIB_ROOT }}/configure \
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

    rm -rf {{ LIBPNG_BUILD }}
    mkdir {{ LIBPNG_BUILD }}

[unix]
libpng: zlib libpng_wget
    cd {{ LIBPNG_BUILD }}/ && \
        CC="{{LIBAFL_CC}}" \
        CFLAGS="-I{{ ZLIB_INCLUDE }}" \
        CPPFLAGS="-I{{ ZLIB_INCLUDE }}" \
        LDFLAGS="-L{{ ZLIB_LIB }}" \
        {{ DEPS_DIR }}/libpng-1.6.37/configure \
            --enable-shared=no \
            --with-pic=yes \
            --enable-hardware-optimizations={{ OPTIMIZATIONS }}

    make -j -C {{ TARGET_DIR }}/build-png/
