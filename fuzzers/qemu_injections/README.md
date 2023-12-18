# qemu_injections

This folder contains an example fuzzer for finding SQL injections in sqlite3
and command injections.

The following architecture is supported:
* x86_64

To configure to catch the injections you are interested in just modify
the `injections.yaml` file.

Detecting command injections does not require any configuration.


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
