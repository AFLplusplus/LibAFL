FUZZER_NAME="fuzzer"
PROJECT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
UNAME := $(shell uname)
LIB_DIR := $(PROJECT_DIR)/target/release/libafl_atheris.a

PHONY: all

all: fuzzer

atheris:
	git clone https://github.com/google/atheris.git

target/release/libafl_atheris.a: src/*
	# Build the libpng libfuzzer library
	cargo build --release

fuzzer: target/release/libafl_atheris.a atheris env
	(\
	source env/bin/activate; \
	cd atheris; \
	LIBFUZZER_LIB=$(LIB_DIR) pip install .; \
	)

clean:
	rm env

run: all
	./$(FUZZER_NAME) --cores 0 &

env:
	python3 -m pip install --user virtualenv
	python3 -m venv env

short_test: all
	(\
	rm -rf libafl_unix_shmem_server || true; \
	source env/bin/activate; \
	RUST_BACKTRACE=1 timeout 10s python3 ./atheris/example_fuzzers/fuzzing_example.py --cores 0; \
	)

test: all
	(\
	rm -rf libafl_unix_shmem_server || true; \
	source env/bin/activate; \
	RUST_BACKTRACE=1 timeout 60s python3 ./atheris/example_fuzzers/fuzzing_example.py --cores 0 --input in; \
	)
