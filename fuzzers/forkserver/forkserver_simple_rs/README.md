# Simple Rust-only Forkserver Fuzzer

A minimal forkserver fuzzer with a pure Rust target binary — no C toolchain required.

## Build

```
cargo build --release
```

This produces two binaries:
- `target/release/forkserver_simple_rs` — the fuzzer driver
- `target/release/target` — the harness program

Optional features:
- `shared_input_mem` — deliver inputs via shared memory instead of stdin
- Build both target and fuzzer with `--features shared_input_mem`

## Run

```
# Non-persistent mode
./target/release/forkserver_simple_rs

# Persistent mode (~6x faster)
./target/release/forkserver_simple_rs -p
```

Seeds are loaded from `./corpus/` if present; otherwise a single zero byte is used.

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-p` | Persistent mode | off |
| `-t` | Timeout per execution (ms) | 1200 |
| `-d` | Print child stdout/stderr | off |
| `-s` | Kill signal | SIGKILL |

## Harness

The target (`src/target.rs`) is a synthetic example: it sets coverage as each character
of `"bad"` is matched and crashes on the full prefix — the fuzzer must evolve a `0x00`
seed into `"bad"`.
