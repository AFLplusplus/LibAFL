FUZZER_NAME="fuzzer_libpng"
PROJECT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
UNAME := $(shell uname)

PHONY: all

all: fuzzer

libpng-1.6.37:
	wget https://deac-fra.dl.sourceforge.net/project/libpng/libpng16/1.6.37/libpng-1.6.37.tar.xz
	tar -xvf libpng-1.6.37.tar.xz

target/release/libafl_cxx: src/* src/bin/*
	# Build the libpng libfuzzer library
	cargo build --release

libafl_cxx: target/release/libafl_cxx

libafl_cc: target/release/libafl_cxx

libpng-1.6.37/.libs/libpng16.a: libpng-1.6.37 libafl_cc
	cd libpng-1.6.37 && ./configure
	$(MAKE) -C libpng-1.6.37 CC="$(PROJECT_DIR)/target/release/libafl_cc" CXX="$(PROJECT_DIR)/target/release/libafl_cxx"
	

fuzzer: libpng-1.6.37/.libs/libpng16.a libafl_cxx
	# Build the libpng libfuzzer library
	cargo build --release

	# Build the libpng harness	
	target/release/libafl_cxx \
		$(PROJECT_DIR)/harness.cc \
		$(PROJECT_DIR)/libpng-1.6.37/.libs/libpng16.a \
		-I$(PROJECT_DIR)/libpng-1.6.37/ \
		-o $(FUZZER_NAME) \
		-lm -lz

clean:
	rm ./$(FUZZER_NAME)
	$(MAKE) -C libpng-1.6.37 clean

run: all
	./$(FUZZER_NAME) --cores 0 &

ifeq ($(UNAME), Darwin)
short_test: libafl_cc
	$(warning "The libpng linking step is currently broken on MacOS! See Issue #246")

else
short_test: all
	rm -rf libafl_unix_shmem_server || true
	timeout 10s ./$(FUZZER_NAME) --cores 0 &

endif

test: all
	timeout 60s ./$(FUZZER_NAME) --cores 0 &
