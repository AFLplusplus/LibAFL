# Build
cargo build --release
# Build harness
clang++ -shared -fPIC -o harness.so harness.cpp
# Run

