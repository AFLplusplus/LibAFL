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

You need to add anywhere in your project a `external_current_millis` function, which returns the current time in milliseconds.

// Assume this a clock source from a custom stdlib, which you want to use, which returns current time in seconds.
```c
int my_real_ms_clock(void)
{
    return *CLOCK;
}
```
and here we use it in Rust. `external_current_millis` is then called from LibAFL.
```rust
#[no_mangle]
pub extern "C" fn external_current_millis() -> u64 {
    unsafe { my_real_ms_clock()*1000 }
}
```