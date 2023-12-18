# qemu_injections

This folder contains an example fuzzer for finding SQL injections in sqlite3
and command injections.

The following architecture is supported:
* x86_64

To configure to catch the injections you are interested in just modify
the `injections.yaml` file.

Detecting command injections does not require any configuration.

Note that currently you need your static compiled target or the necessary
shared libs compiled in debug mode (`-g`).

## Prerequisites
```bash
sudo apt install gcc g++ libsqlite3-dev
```

## Run

```
make static  # compile the target
cargo build  # build the injection fuzzer
cargo run -- -y injections.yaml -i in -o out -- ./static
```

## Other work

- 2023: Toss a Fault to Your Witcher: Applying Grey-box Coverage-Guided Mutational Fuzzing to Detect
SQL and Command Injection Vulnerabilities [https://github.com/sefcom/Witcher](https://github.com/sefcom/Witcher)
  Uses fault/error detection via LD_PRELOAD for sql injection and command injection.
- 2023: oss-fuzz System Sanitizers [https://github.com/google/oss-fuzz/tree/master/infra/experimental/SystemSan](https://github.com/google/oss-fuzz/tree/master/infra/experimental/SystemSan)
  Uses ptrace to hook execve and see if a specific canary binary is executed, similar to the approach used by us.
