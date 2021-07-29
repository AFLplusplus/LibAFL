FUZZER_NAME=fuzzbench_qemu
PROJECT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

ifeq ($(strip $(CPU_TARGET)),)
  CPU_TARGET=$(shell uname -m)
  ifeq ($(strip $(CPU_TARGET)),i686)
    CPU_TARGET=i386
  else ifeq ($(strip $(CPU_TARGET)),arm64v8)
    CPU_TARGET=aarch64
  endif
endif

ifeq ($(strip $(BUILD_TARGET)),)
  BUILD_TARGET=release
endif

ifeq ($(strip $(DEBUG)),1)
  BUILD_TARGET=debug
endif

ifeq ($(strip $(BUILD_TARGET)),release)
  CARGO_ARGS+= --release
endif

UNAME := $(shell uname)

.PHONY: clean short_test all

all: build/qemu-$(CPU_TARGET)

target/$(BUILD_TARGET)/lib$(FUZZER_NAME).a: src/*
	cargo build $(CARGO_ARGS)

qemu-libafl-bridge:
	git clone git@github.com:AFLplusplus/qemu-libafl-bridge.git
	cd qemu-libafl-bridge && git checkout ae096f10cec9a0ac489cb6e6c9892bcbfaea159d

build/config.status: qemu-libafl-bridge qemu-libafl-bridge/configure
	mkdir -p build
	cd build && ../qemu-libafl-bridge/configure --target-list=$(CPU_TARGET)-linux-user --with-libafl-bridge="$(PROJECT_DIR)/target/$(BUILD_TARGET)/lib$(FUZZER_NAME).a"

build/qemu-$(CPU_TARGET): target/$(BUILD_TARGET)/lib$(FUZZER_NAME).a build/config.status
	$(MAKE) -C build

pull: qemu-libafl-bridge
	cd qemu-libafl-bridge && git pull

clean:
	rm -rf build
	cargo clean

ifeq ($(UNAME), Linux)

short_test: target/$(BUILD_TARGET)/lib$(FUZZER_NAME).a
	@echo "Skipping short test"

else

short_test:
	@echo "Skipping build and short test"

endif
