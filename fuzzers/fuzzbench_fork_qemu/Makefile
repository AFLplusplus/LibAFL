FUZZER_NAME="libpng_harness"
PROJECT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
UNAME := $(shell uname)

PHONY: all

all: fuzzer

libpng-1.6.37:
	wget https://deac-fra.dl.sourceforge.net/project/libpng/libpng16/1.6.37/libpng-1.6.37.tar.xz
	tar -xvf libpng-1.6.37.tar.xz

target/release/fuzzbench_qemu: src/*
	cargo build --release

libpng-1.6.37/.libs/libpng16.a: libpng-1.6.37
	cd libpng-1.6.37 && ./configure --enable-shared=no --with-pic=yes --enable-hardware-optimizations=yes
	$(MAKE) -C libpng-1.6.37
	cc -c $(PROJECT_DIR)/libfuzzer_main.c
	# Build the libpng harness	
	c++ \
		$(PROJECT_DIR)/../libfuzzer_libpng/harness.cc \
		$(PROJECT_DIR)/libpng-1.6.37/.libs/libpng16.a \
		libfuzzer_main.o \
		-I$(PROJECT_DIR)/libpng-1.6.37/ \
		-o $(FUZZER_NAME) \
		-lm -lz

fuzzer: target/release/fuzzbench_qemu libpng-1.6.37/.libs/libpng16.a

clean:
	rm ./$(FUZZER_NAME) libfuzzer_main.o
	$(MAKE) -C libpng-1.6.37 clean

run: all
	cargo run --release -- --libafl-in ../libfuzzer_libpng/corpus --libafl-out ./out ./$(FUZZER_NAME)

short_test: all
	rm -rf libafl_unix_shmem_server || true
	timeout 10s cargo run --release -- --libafl-in ../libfuzzer_libpng/corpus --libafl-out ./out ./$(FUZZER_NAME) &

test: all
	timeout 60s cargo run --release -- --libafl-in ../libfuzzer_libpng/corpus --libafl-out ./out ./$(FUZZER_NAME) &
