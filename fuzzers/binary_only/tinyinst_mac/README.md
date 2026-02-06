# TinyInst macOS example

This is a TinyInst-based fuzzer for macOS Apple Silicon, targeting the ImageIO framework.
The harness is from [Jackalope](https://github.com/googleprojectzero/Jackalope) examples.

## Build

1. Build the harness

```bash
cd imageio && make
```

2. Build the fuzzer

```bash
cargo build --release
```

Seeds are loaded from `seeds/pngs/` in the repo root.

## Run

TinyInst needs root for `task_for_pid` on macOS.

```bash
sudo ./target/release/tinyinst_mac
```

Crashes go to `crashes/`.
