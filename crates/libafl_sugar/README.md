# `LibAFL_Sugar`: High-level usable wrappers for `LibAFL`

 <img align="right" src="https://raw.githubusercontent.com/AFLplusplus/Website/main/static/libafl_logo.svg" alt="LibAFL logo" width="250" heigh="250">

The `libafl_sugar` crate offers high-level, usable wrappers for `LibAFL`, simplifying common fuzzing tasks and providing a more ergonomic API for building fuzzers. It aims to reduce boilerplate and make `LibAFL` more accessible to new users, while still retaining the flexibility and power of the underlying framework.

## Examples

The following are some ways to write fuzzers with the sugar 🍭 crate.

### In-process fuzzing

```rust
use libafl_sugar::inprocess::InProcessBytesCoverageSugar;
use libafl_bolts::core_affinity::Cores;
use std::path::PathBuf;

let mut harness = |buf: &[u8]| {
    if buf.len() > 0 && buf[0] == b'a' {
        if buf.len() > 1 && buf[1] == b'b' {
            if buf.len() > 2 && buf[2] == b'c' {
                panic!("Three bytes found!");
            }
        }
    }
};

InProcessBytesCoverageSugar::builder()
    .input_dirs(&[PathBuf::from("./in")])
    .output_dir(PathBuf::from("./out"))
    .cores(&Cores::from_core_ids(vec![0]).unwrap())
    .harness(&mut harness)
    .build()
    .run();
```

### Forkserver fuzzing

```rust
use libafl_sugar::forkserver::ForkserverBytesCoverageSugar;
use libafl_bolts::core_affinity::Cores;
use std::path::PathBuf;

ForkserverBytesCoverageSugar::builder()
    .input_dirs(&[PathBuf::from("./in")])
    .output_dir(PathBuf::from("./out"))
    .cores(&Cores::from_core_ids(vec![0]).unwrap())
    .binary(PathBuf::from("./target"))
    .arguments(&["@@"])
    .build()
    .run();
```

### QEMU fuzzing

```rust
use libafl_sugar::qemu::{QemuBytesCoverageSugar, QemuSugarParameter};
use libafl_bolts::core_affinity::Cores;
use std::path::PathBuf;

let mut harness = |buf: &[u8]| {
    if buf.len() > 0 && buf[0] == b'a' {
        if buf.len() > 1 && buf[1] == b'b' {
            if buf.len() > 2 && buf[2] == b'c' {
                panic!("Three bytes found!");
            }
        }
    }
};

let qemu_args = &["-d", "unimp,guest_errors", "-L", "."];

QemuBytesCoverageSugar::builder()
    .input_dirs(&[PathBuf::from("./in")])
    .output_dir(PathBuf::from("./out"))
    .cores(&Cores::from_core_ids(vec![0]).unwrap())
    .harness(&mut harness)
    .build()
    .run(QemuSugarParameter::QemuCli(qemu_args));
```

## The `LibAFL` Project

The `LibAFL` project is part of [`AFLplusplus`](https://github.com/AFLplusplus) and maintained by

* [Andrea Fioraldi](https://twitter.com/andreafioraldi) <andrea@aflplus.plus>
* [Dominik Maier](https://twitter.com/domenuk) <dominik@aflplus.plus>
* [s1341](https://twitter.com/srubenst1341) <github@shmarya.net>
* [Dongjia Zhang](https://github.com/tokatoka) <toka@aflplus.plus>
* [Addison Crump](https://github.com/addisoncrump) <me@addisoncrump.info>

## Contributing

For bugs, feel free to open issues or contact us directly. Thank you for your support. <3

Even though we will gladly assist you in finishing up your PR, try to

* keep all the crates compiling with *stable* rust (hide the eventual non-stable code under `cfg`s.)
* run `cargo nightly fmt` on your code before pushing
* check the output of `cargo clippy --all` or `./clippy.sh`
* run `cargo build --no-default-features` to check for `no_std` compatibility (and possibly add `#[cfg(feature = "std")]`) to hide parts of your code.

Some parts in this list may sound hard, but don't be afraid to open a PR if you cannot fix them by yourself. We will gladly assist.

#### License

<sup>
Licensed under either of <a href="../LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="../LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>

<br>

<sub>
Dependencies under more restrictive licenses, such as GPL or AGPL, can be enabled
using the respective feature in each crate when it is present, such as the
'agpl' feature of the libafl crate.
</sub>
