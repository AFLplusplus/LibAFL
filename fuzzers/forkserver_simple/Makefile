FUZZER_NAME="forkserver_simple"
PROJECT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

PHONY: all

all: $(FUZZER_NAME)

$(FUZZER_NAME):
	cargo build --release
	cp $(PROJECT_DIR)/target/release/$(FUZZER_NAME) .

clean:
	rm ./$(FUZZER_NAME)

run:  all
	taskset -c 0 ./$(FUZZER_NAME) 2>/dev/null &

short_test: all
	rm -rf libafl_unix_shmem_server || true
	timeout 10s taskset -c 0 ./$(FUZZER_NAME) 2>/dev/null &

test: all
	timeout 60s taskset -c 0 ./$(FUZZER_NAME) 2>/dev/null &
