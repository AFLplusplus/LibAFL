# Using LibAFL in no_std environments

It is possible to use LibAFL in `no_std` environments e.g. custom platforms like microcontrolles or similar.

You can simply add LibAFL to your `Cargo.toml` file:

```toml
libafl = { path = "path/to/libafl/", default-features = false}
```

Then build your project e.g. for `aarch64-unknown-none` using
```
cargo build --no-default-features --target aarch64-unknown-none
```

## Use custom timing

TODO: add here how to implement custom timing function when [PR](https://github.com/AFLplusplus/LibAFL/pull/281) is ready.