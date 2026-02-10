# LibAFL Repo Tools

A set of useful tools to manage the LibAFL repository.

## Features

This crate provides a binary `libafl_repo_tools` that helps with:

*   **Formatting**: Running `cargo fmt` and `clang-format` across the repository.
*   **Checking**: Verifying code formatting in CI.
*   **Lockfiles**: Generating `Cargo.lock` files for all crates.

## Usage

To use this tool, you can run it from the root of the repository:

```sh
cargo run -p libafl_repo_tools -- --help
```

Common commands:

*   Format everything: `cargo run -p libafl_repo_tools`
*   Check formatting: `cargo run -p libafl_repo_tools -- --check`
*   Generate lockfiles: `cargo run -p libafl_repo_tools -- --generate-lockfiles`

## Authors

*   [Romain Malmain](mailto:romain.malmain@pm.me)

## Contributing

For bugs, feel free to open issues or contact us directly. Thank you for your support. <3

## License

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
