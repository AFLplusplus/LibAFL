FUZZER_NAME="libafl_frida"
PROJECT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

PHONY: all

all: libafl_frida libpng-harness.so

libpng-1.6.37:
	wget https://deac-fra.dl.sourceforge.net/project/libpng/libpng16/1.6.37/libpng-1.6.37.tar.xz
	tar -xvf libpng-1.6.37.tar.xz

target/release/frida_libpng: src/*
	# Build the frida libpng libfuzzer fuzzer
	cargo build --release

libpng-1.6.37/.libs/libpng16.a: libpng-1.6.37
	cd libpng-1.6.37 && ./configure
	$(MAKE) -C libpng-1.6.37

libpng-harness.so: libpng-1.6.37/.libs/libpng16.a
	$(CXX) -O3 -c -fPIC harness.cc -o harness.o
	$(CXX) -O3 harness.o libpng-1.6.37/.libs/libpng16.a -shared -lz -o libpng-harness.so

libafl_frida: libpng-1.6.37/.libs/libpng16.a target/release/frida_libpng
	cp target/release/frida_libpng libafl_frida

clean:
	rm ./$(FUZZER_NAME)
	$(MAKE) -C libpng-1.6.37 clean

run: all
	./$(FUZZER_NAME) ./libpng-harness.so LLVMFuzzerTestOneInput ./libpng-harness.so --cores=0

short_test: all
	timeout 11s ./$(FUZZER_NAME) ./libpng-harness.so LLVMFuzzerTestOneInput ./libpng-harness.so --cores=0

test: all
	timeout 60s ./$(FUZZER_NAME) ./libpng-harness.so LLVMFuzzerTestOneInput ./libpng-harness.so --cores=0