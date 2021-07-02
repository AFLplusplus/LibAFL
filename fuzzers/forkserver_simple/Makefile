FUZZER_NAME="forkserver_simple"
PROJECT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

PHONY: all

all: fuzzer

fuzzer:
	cargo build --release
	cp $(PROJECT_DIR)/target/release/$(FUZZER_NAME) .

clean:
	rm ./$(FUZZER_NAME)

run:  all
	taskset -c 0 ./$(FUZZER_NAME) 2>/dev/null &
	sleep 0.2

short_test: all
	timeout 11s taskset -c 0 ./$(FUZZER_NAME) 2>/dev/null &

test: all
	timeout 59s taskset -c 0 ./$(FUZZER_NAME) 2>/dev/null &