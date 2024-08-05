# libafl_libfuzzer

`libafl_libfuzzer` is a shim for [libFuzzer] which may be used in place of libFuzzer in most contexts.
It can be used both as a direct shim for existing libFuzzer-compatible targets which are simply linked with libFuzzer
(e.g., `clang -fsanitize=fuzzer`) and as a Rust crate for [`libfuzzer-sys`]-based harnesses.

## Background

`libafl_libfuzzer` was first developed as a shim in light of the [de-facto deprecation of libFuzzer].
Given the widespread use of libFuzzer and that LibAFL already supported most of the instrumentation used by libFuzzer,
we sought to develop a replacement which could directly replace it without much additional effort from the end user.
To do so, `libafl_libfuzzer` provides the same interface and uses the same instrumentation as libFuzzer so that
libFuzzer users can change over to a more modern LibAFL-based runtime without needing extensive changes to their
fuzzing environment or updating their harnesses.

## Usage

`libafl_libfuzzer` currently has known support for Rust, C, and C++ targets on Linux and macOS.
Windows is not currently supported, as we do not currently test or develop for Windows machines, but [we will happily
hear what issues you face and patch them as possible](https://github.com/AFLplusplus/LibAFL/issues/1563).

For both cases, you should install a recent **nightly** version of Rust via `rustup` and add the `llvm-tools` component
with `rustup component add llvm-tools`.

### Usage with Rust harnesses

To use `libafl_libfuzzer` on Rust harnesses which use `libfuzzer-sys`, all you need to do is change the following line
in your Cargo.toml:

```toml
libfuzzer-sys = { version = "...", features = ["your", "features", "here"] }
```

to

```toml
libfuzzer-sys = { version = "0.11.0", features = ["your", "features", "here"], package = "libafl_libfuzzer" }
```

To use the most up-to-date version (with experimental changes), use:

```toml
libfuzzer-sys = { git = "https://github.com/AFLplusplus/LibAFL.git", features = ["your", "features", "here"], package = "libafl_libfuzzer" }
```

As the repository generally offers the highest performance version of `libafl_libfuzzer`, we recommend the latter.
Remember to `cargo update` often if using the experimental changes, and please [submit an issue]
if you encounter problems while using the git branch!

For stability purposes, consider [specifying a commit](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#choice-of-commit).

#### macOS

On macOS, you will need to add weak linking for some functions in a `build.rs` file:

```rust
fn main() {
    for func in [
        "_libafl_main",
        "_LLVMFuzzerCustomMutator",
        "_LLVMFuzzerCustomCrossOver",
    ] {
        println!("cargo:rustc-link-arg=-Wl,-U,{func}");
    }
}
```

#### Caveats

Like harnesses built with `libfuzzer-sys`, Rust targets which build other libraries (e.g. C/C++ FFI) may not
automatically apply instrumentation.
In addition to installing clang, you may also wish to set the following environmental variables:

```bash
CC=clang
CXX=clang++
CFLAGS='-fsanitize=fuzzer-no-link'
CXXFLAGS='-fsanitize=fuzzer-no-link'
```

### Usage as a standalone library (for C/C++/etc.)

The runtime for `libafl_libfuzzer` may be used standalone as a direct replacement for libFuzzer with other targets as
well.
To do so, [ensure a recent nightly version of Rust is installed](https://rustup.rs/), then enter the
[`libafl_libfuzzer_runtime`](../libafl_libfuzzer_runtime) folder and build the runtime with the following command:

```bash
./build.sh
```

The static library will be available at `libFuzzer.a` in the [`libafl_libfuzzer_runtime`](../libafl_libfuzzer_runtime)
directory.
If you encounter build failures without clear error outputs that help you resolve the issue, please [submit an issue].

This library may now be used in place of libFuzzer.
To do so, change your CFLAGS/CXXFLAGS from `-fsanitize=fuzzer` to:

```
-fsanitize=fuzzer-no-link -L/path/to/libafl_libfuzzer_runtime -lFuzzer
```

Alternatively, you may directly overwrite the system libFuzzer library and use `-fsanitize=fuzzer` as normal.
This changes per system, but on my machine is located at `/usr/lib64/clang/16/lib/linux/libclang_rt.fuzzer-x86_64.a`.

#### Caveats

This standalone library is _not_ compatible with Rust targets; you must instead use the crate-based dependency.
This is due to potential symbol conflict between your harness and the fuzzer runtime, which is resolved by additional
build steps provided in the `libafl_libfuzzer` crate itself.

## Flags

You can pass additional flags to the libFuzzer runtime in `cargo-fuzz` like so:

```bash
cargo fuzz run fuzz_target -- -extra_flag=1
```

When the runtime is used standalone, flags may be passed just like normal libFuzzer.

You will commonly need this for flags such as `-ignore_crashes=1` and `-timeout=5`. In addition
to partial support of libfuzzer flags, `libafl_libfuzzer` offers:

- `-dedup=n`, with `n` = 1 enabling deduplication of crashes by stacktrace.
- `-grimoire=n`, with `n` set to 0 or 1 disabling or enabling [grimoire] mutations, respectively.
    - if not specified explicitly, `libafl_libfuzzer` will select based on whether existing inputs are UTF-8
    - you should disable grimoire if your target is not string-like
- `-report=n`, with `n` = 1 causing `libafl_libfuzzer` to emit a report on the corpus content.
- `-skip_tracing=n`, with `n` = 1 causing `libafl_libfuzzer` to disable cmplog tracing.
    - you should do this if your target performs many comparisons on memory sequences which are
      not contained in the input
- `-tui=n`, with `n` = 1 enabling a graphical terminal interface.
    - experimental; some users report inconsistent behaviour with tui enabled

### Supported flags from libfuzzer

- `-merge`
- `-minimize_crash`
- `-artifact_prefix`
- `-timeout`
    - unlike libfuzzer, `libafl_libfuzzer` supports partial second timeouts (e.g. `-timeout=.5`)
- `-dict`
- `-fork` and `-jobs`
    - in `libafl_libfuzzer`, these are synonymous
- `-ignore_crashes`, `-ignore_ooms`, and `-ignore_timeouts`
    - note that setting `-tui=1` enables these flags by default, so you'll need to explicitly mention `-ignore_...=0` to
      disable them
- `-rss_limit_mb` and `-malloc_limit_mb`
- `-ignore_remaining_args`
- `-shrink`
- `-runs`
- `-close_fd_mask`

[libFuzzer]: https://llvm.org/docs/LibFuzzer.html

[`libfuzzer-sys`]: https://docs.rs/libfuzzer-sys/

[de-facto deprecation of libFuzzer]: https://llvm.org/docs/LibFuzzer.html#status

[submit an issue]: https://github.com/AFLplusplus/LibAFL/issues/new/choose

[grimoire]: https://www.usenix.org/conference/usenixsecurity19/presentation/blazytko
