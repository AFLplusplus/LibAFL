# `LibAFL_build`: Build-time utilities for LibAFL

<img align="right" src="https://raw.githubusercontent.com/AFLplusplus/Website/main/static/libafl_logo.svg" alt="LibAFL logo" width="250" heigh="250">

The `libafl_build` crate provides build-time utilities for LibAFL, specifically for detecting LLVM tools and versions. It is used by other LibAFL crates to ensure they are built with the correct LLVM configuration.

## Features

*   **LLVM Tool Detection**: Finds `llvm-config`, `llvm-nm`, `llvm-objcopy`, and other tools, handling versioned binaries (e.g., `llvm-config-15`) and platform-specific paths (e.g., Homebrew on macOS).
*   **Version Detection**: Detects the system LLVM version and the LLVM version used by `rustc`.

## Examples

```rust
use libafl_build::{find_llvm_config, find_llvm_tool, find_llvm_version};

// Find llvm-config
if let Ok(path) = find_llvm_config() {
    println!("Found llvm-config at: {}", path);
}

// Find a specific tool like llvm-nm
if let Ok(path) = find_llvm_tool("llvm-nm") {
    println!("Found llvm-nm at: {}", path);
}

// Check LLVM version
if let Some(version) = find_llvm_version() {
    println!("Detected LLVM version: {}", version);
}
```

## Maintainers

`LibAFL_build` is written and maintained by

* [Andrea Fioraldi](https://twitter.com/andreafioraldi) <andrea@aflplus.plus>
* [Dominik Maier](https://bsky.app/profile/dmnk.bsky.social) <dominik@aflplus.plus>
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
Licensed under either of <a href="../../LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="../../LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>
