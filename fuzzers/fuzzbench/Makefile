FUZZER_NAME="fuzzer"
PROJECT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

PHONY: all

all: fuzzer

target/release/libafl_cxx: src/* src/bin/*
	# Build the libpng libfuzzer library
	cargo build --release

target/release/libafl_cc: target/release/libafl_cxx

fuzz.o: fuzz.c target/release/libafl_cc
	target/release/libafl_cc -O3 -c $^ -o $@

fuzzer: target/release/libafl_cxx fuzz.o
	# Build the fuzzer compiler
	cargo build --release

	# Build the harness	
	target/release/libafl_cxx \
		fuzz.o \
		-o $(FUZZER_NAME) \
		-lm -lz

clean:
	rm ./$(FUZZER_NAME) || true
	rm fuzz.o || true

run: all
	./$(FUZZER_NAME)

short_test: all
	mkdir in || true
	echo a > in/a
	timeout 11s ./$(FUZZER_NAME) out in
	rm -rf out
	rm -rf in

test: all
	mkdir in || true
	echo a > in/a
	timeout 60s ./$(FUZZER_NAME) out in
	rm -rf out
	rm -rf in