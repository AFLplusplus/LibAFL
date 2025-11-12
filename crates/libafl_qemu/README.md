# `LibAFL_QEMU`: A Library for Fuzzing-oriented Emulation and Hooking

`LibAFL_QEMU` is a fuzzing-oriented emulation library that wraps `QEMU` with a rich API in Rust.

It comes in two variants, `usermode` to fuzz Linux ELFs userspace binaries and `systemmode`, to fuzz arbitrary operating systems with QEMU TCG.

## Usage

To use `libafl_qemu` in your project, add it as a dependency in your `Cargo.toml`:

```toml
[dependencies]
# Set this to the latest version
libafl_qemu = { version = "0.16.0", features = ["usermode", "x86_64"] }
```

`libafl_qemu` offers several feature flags to customize its build for different use cases. These flags are typically enabled in your `Cargo.toml`.

## Modes

* `usermode`: Enables fuzzing of userspace binaries on Linux.
* `systemmode`: Enables fuzzing of arbitrary operating systems with `QEMU` TCG. This is mutually exclusive with `usermode`.

## Cite

If you use LibAFL QEMU for your academic work, consider citing the follwing paper:

```bibtex
@InProceedings{libaflqemu:bar24,
  title        = {{LibAFL QEMU: A Library for Fuzzing-oriented Emulation}},
  author       = {Romain Malmain and Andrea Fioraldi and Aurélien Francillon},
  year         = {2024},
  series       = {BAR 24},
  month        = {March},
  booktitle    = {Workshop on Binary Analysis Research (colocated with NDSS Symposium)},
  location     = {San Diego (USA)},
  keywords     = {fuzzing, emulation},
}
```
