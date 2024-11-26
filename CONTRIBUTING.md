# How to Contribute to LibAFL

For bugs, feel free to open issues or contact us directly. Thank you for your support. <3

## Pull Request guideline

Even though we will gladly assist you in finishing up your PR, try to:

- keep all the crates compiling with *stable* rust (hide the eventual non-stable code under [`cfg`s](https://github.com/AFLplusplus/LibAFL/blob/main/libafl/build.rs#L26))
- run `cargo +nightly fmt` on your code before pushing
- check the output of `cargo clippy --all` or `./scripts/clippy.sh` (On windows use `.\scripts\clippy.ps1`)
- run `cargo build --no-default-features` to check for `no_std` compatibility (and possibly add `#[cfg(feature = "std")]`) to hide parts of your code.
- Please add and describe your changes to MIGRATION.md if you change the APIs.

Some of the parts in this list may be hard, don't be afraid to open a PR if you cannot fix them by yourself, so we can help.

### Pre-commit hooks

Some of these checks can be performed automatically during commit using [pre-commit](https://pre-commit.com/).
Once the package is installed, simply run `pre-commit install` to enable the hooks, the checks will run automatically before the commit becomes effective.
