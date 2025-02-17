# GDB-QEMU
`gdb-qemu` is a launcher for running `qemu-user` within `gdb`.

# Test
```
rustup target add powerpc-unknown-linux-gnu
$ just gdb
```

# Example
```
gdb-multiarch \
  -ex "set architecture powerpc:MPC8XX" \
  -ex "set pagination off" \
  -ex "set confirm off" \
  -ex "file demo" \
  -ex "target remote | gdb-qemu -p 1234 qemu-ppc -- -L /usr/powerpc-linux-gnu -g 1234 demo
```

# About
`qemu-gdb` does the following:
* Creates two pipes for the target program to send its `stdout`, `stderr`.
* Forks a child process and sets the `stdout` and `stderr` using `dup2`.
* Exec's the target program (passing the provided arguments).
* Connects to the specified TCP debug port on the target program.
* Forwards data from `gdb-qemu`'s `stdin` and `stdout` to the TCP port.
* Forwards data from the target program's `stdout` and `stderr` to `gdb-qemu`s `stderr`.
* Optionally logs to the specified log file.
* Optionally logs trace information of the data transferred by the message pumps.

# Usage
```
Tool launching qemu-user for debugging

Usage: gdb-qemu [OPTIONS] --port <PORT> <PROGRAM> [-- <ARGS>...]

Arguments:
  <PROGRAM>
          Name of the qemu-user binary to launch

  [ARGS]...
          Arguments passed to the target

Options:
  -p, --port <PORT>
          Port

  -t, --timeout <TIMEOUT>
          Timeout Ms

          [default: 2000]

  -l, --log-file <LOG_FILE>
          Log file (Requires --log-level)

          [default: gdb_qemu.log]

  -L, --log-level <LOG_LEVEL>
          Log level

          [default: off]
          [possible values: off, error, warn, info, debug, trace]

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```
