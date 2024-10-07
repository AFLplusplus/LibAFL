# LIBAFL_JUMPER

If you want to replace your unicorn use with `libafl_qemu`, this might be your tool.
It can run as stub binary.
From inside LibAFL, you can break at `jmp`, then mmap and load all of the memory you need,
then continue running.

Depending on your toolchain, you want to build the tool for the guest platform.
Since the loader will run inside `qemu-linux-user`, the target OS needs to be `linux`
(Of course, there might be other use cases for you).

To build this for arm with `no-std`, we can do the following:

```sh
# Install the new toolchain
rustup target add armv7a-none-eabi
# Install the stdlib source (for some tier2/tier3 targets there are no prebuilts)
rustup component add rust-src
# Build for the target.
cargo +nightly build -Zbuild-std=core --target=armv7a-none-eabi --profile=release 
```

Enjoy jumping like a little bunny.
