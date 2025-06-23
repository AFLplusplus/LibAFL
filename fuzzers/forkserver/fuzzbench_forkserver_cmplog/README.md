# FuzzBench Forkserver CmpLog Fuzzer

This is a forkserver-based fuzzer using CmpLog instrumentation for enhanced fuzzing effectiveness. It demonstrates the use of LibAFL with comparative logging (CmpLog) to improve fuzzing by tracking comparison operations in the target program.

CmpLog instrumentation helps the fuzzer understand comparison operations in the target code, allowing it to generate more meaningful inputs by solving constraints automatically.

## Build

You can build this example by running:
```bash
cargo build --release
```

This will compile the fuzzer. The test program needs to be compiled separately using AFL++ instrumentation.

## Compile Test Program

The test program (`test-cmplog.c`) needs to be compiled with AFL++ instrumentation. You can either:

1. Use the provided script:
```bash
cd test && ./compile.sh
```

2. Or use the justfile (recommended):
```bash
just compile
```

This creates two versions of the test program:
- `test-cmplog.afl`: Regular AFL instrumentation
- `test-cmplog.cmplog`: CmpLog instrumentation for comparison tracking

## Run

### Using Justfile (Recommended)

#### List all available commands
```bash
just
```

#### Prepare and run everything
```bash
just run
```

#### Quick test (10 seconds)
```bash
just quick-test
```

#### Run in release mode (faster)
```bash
just run-release
```

#### Clean and restart
```bash
just clean && just run
```

### Manual Execution

After building the fuzzer and compiling the test program, you can run:

```bash
# Create corpus and output directories
mkdir -p corpus output
echo "test" > corpus/test.txt

# Run the fuzzer
./target/release/fuzzbench_forkserver_cmplog -i ./corpus/ -o ./output/ ./test-cmplog.afl --cmplog ./test-cmplog.cmplog
```