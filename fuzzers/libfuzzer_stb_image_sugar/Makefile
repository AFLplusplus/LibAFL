FUZZER_NAME="libfuzzer_stb_image"
PROJECT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

PHONY: all

all: fuzzer

target/release/libafl_cxx: build.rs
	# Build the libpng libfuzzer library
	cargo build --release

libafl_cxx: target/release/libafl_cxx

libafl_cc: target/release/libafl_cxx

fuzzer: libafl_cxx
	# Build the libpng libfuzzer library
	cargo build --release
	cp $(PROJECT_DIR)/target/release/$(FUZZER_NAME) .

clean:
	rm ./$(FUZZER_NAME)

run: all
	./$(FUZZER_NAME) &
	sleep 0.2
	./$(FUZZER_NAME) >/dev/null 2>/dev/null &

short_test: all
	rm -rf libafl_unix_shmem_server || true
	timeout 11s ./$(FUZZER_NAME) &
	sleep 0.2
	timeout 10s taskset -c 0 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	timeout 10s taskset -c 1 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	timeout 10s taskset -c 2 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	timeout 10s taskset -c 3 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &

test: all
	timeout 60s ./$(FUZZER_NAME) &
	sleep 0.2
	timeout 59s taskset 0x00000001 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	timeout 59s taskset 0x00000002 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	timeout 59s taskset 0x00000004 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	timeout 59s taskset 0x00000008 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00000010 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00000020 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00000040 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00000080 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00000100 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00000200 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00000400 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00000800 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00001000 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00002000 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00004000 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00008000 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00010000 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00020000 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00040000 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00080000 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00100000 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00200000 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00400000 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00800000 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x01000000 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x02000000 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x04000000 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x08000000 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x10000000 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x20000000 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x40000000 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x80000000 ./$(FUZZER_NAME) >/dev/null 2>/dev/null &
