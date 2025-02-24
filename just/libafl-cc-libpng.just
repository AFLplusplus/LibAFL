import "libafl-cc.just"

ARCH := env("ARCH", "x86_64")
OPTIMIZATIONS := env("OPTIMIZATIONS", if ARCH == "ppc" { "no" } else { "yes" })

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
    wget -O "{{ DEPS_DIR }}/zlib-1.2.13.tar.gz" https://zlib.net/fossils/zlib-1.2.13.tar.gz

    tar zxvf {{ DEPS_DIR }}/zlib-1.2.13.tar.gz -C {{ DEPS_DIR }}

[unix]
zlib feat: zlib_wget (cc feat)
    rm -rf {{ ZLIB_BUILD }}
    mkdir {{ ZLIB_BUILD }}

    cd {{ ZLIB_BUILD }} && CC={{ LIBAFL_CC }} {{ ZLIB_ROOT }}/configure --prefix=./zlib

    make -j -C {{ ZLIB_BUILD }} install

[unix]
libpng_wget: deps_dir
    wget -O "{{ DEPS_DIR }}/v1.6.37.tar.gz" https://github.com/glennrp/libpng/archive/refs/tags/v1.6.37.tar.gz

    tar -xvf "{{ DEPS_DIR }}/v1.6.37.tar.gz" -C {{ DEPS_DIR }}

    rm -rf {{ LIBPNG_BUILD }}
    mkdir {{ LIBPNG_BUILD }}

[unix]
libpng feat: (zlib feat) libpng_wget (cc feat)
    cd {{ LIBPNG_BUILD }}/ && \
        CC="{{LIBAFL_CC}}" \
        CFLAGS="-I{{ ZLIB_INCLUDE }}" \
        CPPFLAGS="-I{{ ZLIB_INCLUDE }}" \
        LDFLAGS="-L{{ ZLIB_LIB }}" \
        {{ DEPS_DIR }}/libpng-1.6.37/configure \
            --enable-shared=no \
            --with-pic=yes \
            --enable-hardware-optimizations={{ OPTIMIZATIONS }}

    make -j -C {{ LIBPNG_BUILD }}
