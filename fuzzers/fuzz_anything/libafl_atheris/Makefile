PROJECT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
UNAME :="$(shell uname)"
LIB_DIR :="$(PROJECT_DIR)/target/release/libafl_atheris.a"
DEEXIT_PATH = "$(PROJECT_DIR)/../../target/release/libdeexit.dylib"

ifeq ("$(wildcard $(DEEXIT_PATH))", "")
	DEEXIT_PATH = "$(PROJECT_DIR)/../../target/release/libdeexit.so"
endif

PHONY: all

all: fuzzer deexit

deexit: $(DEEXIT_PATH)

$(DEEXIT_PATH):
	cd ../.. && cargo build --release -p deexit

atheris:
	git clone https://github.com/google/atheris.git

target/release/libafl_atheris.a: src/*
	# Build the libpng libfuzzer library
	cargo build --release

fuzzer: target/release/libafl_atheris.a atheris env
	(\
	. env/bin/activate; \
	pip install wheel; \
	cd atheris; \
	LIBFUZZER_LIB=$(LIB_DIR) pip install .; \
	)

clean:
	rm -rf env

env:
	python3 -m venv env

short_test: all
	(\
	rm -rf libafl_unix_shmem_server || true; \
	. env/bin/activate; \
	LD_PRELOAD=$(DEEXIT_PATH) DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES=$(DEEXIT_PATH) RUST_BACKTRACE=1 timeout 30s python3 ./atheris/example_fuzzers/fuzzing_example.py --cores 0 -i in -o out || true; \
	rm -rf out; \
	)

test:
	(\
	rm -rf libafl_unix_shmem_server || true; \
	. env/bin/activate; \
	LD_PRELOAD=$(DEEXIT_PATH) DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES=$(DEEXIT_PATH) RUST_BACKTRACE=1 timeout 60s python3 ./atheris/example_fuzzers/fuzzing_example.py --cores 0 -i in -o out || true; \
	rm -rf out; \
	)
