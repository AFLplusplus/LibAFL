# LIBAFL_QEMU_JUMPEr

If you want to replace your unicorn use with libafl_qemu, this might be your tool.
It can run as stub binary.
From inside LibAFL, you can break at `jmp`, then mmap and load all of the memory you need,
then continue running.

Depending on your toolchain, you want to build the tool for the guest platform.
Since the loader will run inside linux-user, the target OS needs to be `linux`.
Ideally, you use a `musl` variant since it does not require a functioning libc.
So we can do the following:

```sh
# Install the new toolchain
rustup target add arm-unknown-linux-musleabi
# Install the stdlib source (for some tier2/tier3 targets there are no prebuilts)
rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu
# Build for the target.
cargo +nightly build --target=arm-unknown-linux-musleabi -Zbuild-std --profile=release
```

Enjoy jumping like a little bunny.