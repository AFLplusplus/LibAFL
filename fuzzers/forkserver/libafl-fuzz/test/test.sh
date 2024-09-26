#!/bin/bash

export AFL_DIR_NAME="./AFLplusplus-stable"
export AFL_CC_PATH="$AFL_DIR_NAME/afl-clang-fast"
export LIBAFL_FUZZ_PATH="../target/release/libafl-fuzz"
export LLVM_CONFIG="llvm-config-18"
if [ ! -d "$AFL_DIR_NAME" ]; then
	wget https://github.com/AFLplusplus/AFLplusplus/archive/refs/heads/stable.zip
	unzip stable.zip
	cd $AFL_DIR_NAME
	LLVM_CONFIG=$LLVM_CONFIG make 
	cd ..
fi

cargo build --release


AFL_PATH=$AFL_DIR_NAME $AFL_CC_PATH $AFL_DIR_NAME/test-instr.c -o out-instr

AFL_CORES=1 LLVM_CONFIG=${LLVM_CONFIG} AFL_STATS_INTERVAL=1 AFL_NUM_CORES=1 timeout 5 $LIBAFL_FUZZ_PATH -i ./seeds -o ./output $(pwd)/out-instr
test -n "$( ls output/fuzzer_main/queue/id:000002* 2>/dev/null )" || exit 1
test -n "$( ls output/fuzzer_main/fuzzer_stats 2>/dev/null )" || exit 1
test -n "$( ls output/fuzzer_main/plot_data 2>/dev/null )" || exit 1
test -n "$( ls output/fuzzer_main/crashe2s 2>/dev/null )" || exit 1
test -n "$( ls output/fuzzer_main/hangs 2>/dev/null )" || exit 1
