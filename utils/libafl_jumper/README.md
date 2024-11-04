# LIBAFL_JUMPER

If you want to replace your unicorn use with `libafl_qemu`, this might be your tool.
It can run as stub binary.
From inside LibAFL, you can break at `jmp`, then mmap and load all of the memory you need,
then continue running.

Depending on your toolchain, you want to build the tool for the guest platform.
Since the loader will run inside `qemu-linux-user`, the target OS needs to be `linux`
(Of course, there might be other use cases for you).

To build this statically linked with `musl` libc, we can do the following:

```sh
# Install cross compiler toolchain
apt-get install gcc-arm-linux-gnueabihf
# Install the rust toolchain parts
rustup target add arm-unknown-linux-musleabi
# Build for the target. The addresses in the linker script should not be used by your target binary.
RUSTFLAGS="-C target-feature=+crt-static, -C link-self-contained=yes -C linker=arm-linux-gnueabi-gcc -C link-arg=T$(realpath linker_script.ld)" cargo build --target=arm-unknown-linux-musleabi --release
```

↪ Or do that for any other architecture, such as `x86_64-unknown-linux-musl`.

Then, you can run libafl_jumper with a hex-encoded address as parameter, and break at the `libafl_jmp` and (m)map your memory to the right place in memory, before continuing to run.
The jumper will then jump to the provided address.

Enjoy jumping like a little bunny.
