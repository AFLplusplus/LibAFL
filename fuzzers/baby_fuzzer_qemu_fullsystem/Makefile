FUZZER_NAME=baby_fuzzer_qemu_fullsystem
PROJECT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

CPU_TARGET = aarch64-softmmu
# ifeq ($(strip $(CPU_TARGET)),)
#   CPU_TARGET=$(shell uname -m)-softmmu
#   ifeq ($(strip $(CPU_TARGET)),i686)
#     CPU_TARGET=i386-softmmu
#   else ifeq ($(strip $(CPU_TARGET)),arm64v8)
#     CPU_TARGET=aarch64-softmmu
#   endif
# endif

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

all: build/qemu-$(CPU_TARGET)-system

target/$(BUILD_TARGET)/lib$(FUZZER_NAME).a: src/* Cargo.toml Cargo.lock
	cargo build $(CARGO_ARGS)

qemu-libafl-bridge:
	git clone git@github.com:bitwave/qemu-libafl-bridge.git
	cd qemu-libafl-bridge && git checkout a8da66f47c57ae5502b6c1a1e1ba04e6231cfdbe

build/config.status: qemu-libafl-bridge qemu-libafl-bridge/configure
	mkdir -p build
	cd build && ../qemu-libafl-bridge/configure --target-list=$(CPU_TARGET) --with-libafl-bridge="$(PROJECT_DIR)/target/$(BUILD_TARGET)/lib$(FUZZER_NAME).a"

build/qemu-$(CPU_TARGET)-system: target/$(BUILD_TARGET)/lib$(FUZZER_NAME).a build/config.status
	$(MAKE) -C build qemu-system-aarch64

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
