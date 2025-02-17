# nyx_launcher

Example fuzzer based on `qemu_launcher` but for Nyx.

## Run the fuzzer

Run with an existing nyx shared dir:

```
cargo run -- --input input/ --output output/ --share /tmp/shareddir/ --buffer-size 4096 --cores 0-1 -v --cmplog-cores 1
```
