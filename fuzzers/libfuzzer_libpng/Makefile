PWD=`pwd`

all:
	# Build the libpng libfuzzer library
	cargo build --release

    # Build the libpng harness	
	$(PWD)/target/release/cxx \
		$(PWD)/harness.cc \
		$(PWD)/libpng-1.6.37/.libs/libpng16.a \
		-I$(PWD)/libpng-1.6.37/ \
		-o fuzzer \
		-lm -lz

run: all
	./fuzzer &
	./fuzzer >/dev/null 2>/dev/null &

test: all
	timeout 60s ./fuzzer &
	timeout 59s taskset 0x00000001 ./fuzzer >/dev/null 2>/dev/null &
	timeout 59s taskset 0x00000002 ./fuzzer >/dev/null 2>/dev/null &
	timeout 59s taskset 0x00000004 ./fuzzer >/dev/null 2>/dev/null &
	timeout 59s taskset 0x00000008 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00000010 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00000020 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00000040 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00000080 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00000100 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00000200 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00000400 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00000800 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00001000 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00002000 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00004000 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00008000 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00010000 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00020000 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00040000 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00080000 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00100000 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00200000 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00400000 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x00800000 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x01000000 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x02000000 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x04000000 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x08000000 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x10000000 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x20000000 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x40000000 ./fuzzer >/dev/null 2>/dev/null &
	# timeout 59s taskset 0x80000000 ./fuzzer >/dev/null 2>/dev/null &
