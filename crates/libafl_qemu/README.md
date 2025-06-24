# LibAFL QEMU

LibAFL QEMU is a fuzzing-oriented emulation library that wraps QEMU with a rich API in Rust.

It comes in two variants, usermode to fuzz Linux ELFs userspace binaries and systemmode, to fuzz arbitrary operating systems with QEMU TCG.

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


