FUZZER_NAME="fuzzer"
PROJECT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
UNAME := $(shell uname)

PHONY: all

all: fuzzer

target/release/libafl_cxx: src/* src/bin/*
	# Build the libpng libfuzzer library
	cargo build --release

libafl_cxx: target/release/libafl_cxx

libafl_cc: target/release/libafl_cxx

fuzzer: libafl_cc
	target/release/libafl_cc -O3 fuzz.c -o $@

clean:
	rm ./$(FUZZER_NAME)

run: all
	./$(FUZZER_NAME) --cores 0 &

short_test: all
	rm -rf libafl_unix_shmem_server || true
	RUST_BACKTRACE=1 timeout 10s ./$(FUZZER_NAME) --cores 0 &

test: all
	RUST_BACKTRACE=1 timeout 60s ./$(FUZZER_NAME) --cores 0 &
