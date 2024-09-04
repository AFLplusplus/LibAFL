#!/bin/bash

if [ ! -d "sqlite3" ]; then
    curl 'https://sqlite.org/src/tarball/sqlite.tar.gz?r=c78cbf2e86850cc6' -o sqlite3.tar.gz && mkdir sqlite3 && pushd sqlite3 && tar xzf ../sqlite3.tar.gz --strip-components 1 && popd
    mkdir corpus
    find ./sqlite3 -name "*.test" -exec cp {} corpus/ \;
fi

if [ "$1" = "d" ]; then
  cargo build
else
  cargo build --release
fi

export CC=`pwd`/target/release/libafl_cc
export CXX=`pwd`/target/release/libafl_cxx
export CFLAGS='--libafl'
export CXXFLAGS='--libafl'
export CFLAGS="$CFLAGS -DSQLITE_MAX_LENGTH=128000000 \
               -DSQLITE_MAX_SQL_LENGTH=128000000 \
               -DSQLITE_MAX_MEMORY=25000000 \
               -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
               -DSQLITE_DEBUG=1 \
               -DSQLITE_MAX_PAGE_COUNT=16384"
pushd sqlite3

if [ ! -f "Makefile" ]; then
    echo "Run configure..."
    ./configure
fi
make -j$(nproc)
make sqlite3.c
popd

if [ "$1" = "release" ]; then
  ./target/release/libafl_cc --libafl -I ./sqlite3 -c ./sqlite3/test/ossfuzz.c -o ./sqlite3/test/ossfuzz.o
  ./target/release/libafl_cxx --libafl -o ossfuzz ./sqlite3/test/ossfuzz.o ./sqlite3/sqlite3.o -pthread -ldl -lz
else
  ./target/debug/libafl_cc --libafl -I ./sqlite3 -c ./sqlite3/test/ossfuzz.c -o ./sqlite3/test/ossfuzz.o
  ./target/debug/libafl_cxx --libafl -o ossfuzz ./sqlite3/test/ossfuzz.o ./sqlite3/sqlite3.o -pthread -ldl -lz
fi

