# LibAFL DrCov Utilities

## Dump-DrCov_Addrs

Simple commandline tool to display a list of all basic block addresses in a program.
This information can, for example, be used for further processing such as in [JmpScare](https://github.com/fgsect/JMPscare) or similar.
At the same time this tools shows how easily LibAFL's `DrCov` module can be used to parse coverage files.

Run with `cargo run --release --bin drcov_dump_addrs -- -h`

## DrCov_Merge

A performant clone of [drcov-merge](https://github.com/vanhauser-thc/drcov-merge) using LibAFL's `DrCov` reader.
It can merge multiple DrCov files into a single DrCov file.

Run with `cargo run --release --bin drcov_merge -- -h`
For example `cargo run --release --bin drcov_merge -- -o merged.cov -i *`
