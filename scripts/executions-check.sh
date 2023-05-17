#!/bin/bash
install_libpng() {
	cd ./fuzzers/libfuzzer_libpng && wget https://deac-fra.dl.sourceforge.net/project/libpng/libpng16/1.6.37/libpng-1.6.37.tar.xz 
	tar -xvf libpng-1.6.37.tar.xz || echo "Failed to download libpng" 
	cd libpng-1.6.37 && ./configure --enable-shared=no --with-pic=yes --enable-hardware-optimizations=yes && cd ..
}

build_libpng(){
	cargo build --release || echo "ERROR: Failed to build libfuzzer_libpng" 

	cd libpng-1.6.37 && make CC="$(pwd)/../target/release/libafl_cc" CXX="$(pwd)/../target/release/ libafl_cxx" -j "$(nproc)" && cd ..
}

git_checkout(){
	git reset --hard HEAD^
}

build_run_fuzzer(){
	./target/release/libafl_cxx ./harness.cc libpng-1.6.37/.libs/libpng16.a -I libpng-1.6.37/ -o fuzzer_libpng -lz -lm || exit 2

	./fuzzer_libpng > log.txt &
	
    # wait that fuzzer_libpng become the broker 
    sleep 1

	timeout 5m ./fuzzer_libpng > /dev/null 2>&1 &

	while true; do
		if grep -q "Broker" log.txt ; then
			pkill -9 "fuzzer_libpng"
			executions=$(grep  -m 1 "Broker" log.txt  | awk '{print $14}')
			rm -rf ./libafl_unix_shmem_server
			echo "${executions%,}"
			break
   		fi
	done
}

main(){
	install_libpng

	build_libpng
	echo "start to run the new fuzzer"
	new_executions=$(build_run_fuzzer)

	git_checkout

	build_libpng
	echo "start to run the last fuzzer"
	last_executions=$(build_run_fuzzer)	

	echo "the execution count of the new fuzzer is $new_executions"
	echo "the execution count of the last fuzzer is $last_executions"
}

main
