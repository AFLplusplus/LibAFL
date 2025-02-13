# Binary-only Fuzzing with Frida

LibAFL supports different instrumentation engines for binary-only fuzzing.
A potent cross-platform (Windows, MacOS, Android, Linux, iOS) option for binary-only fuzzing is Frida; the dynamic instrumentation tool.

In this section, we will talk about the components in fuzzing with `libafl_frida`.
You can take a look at a working example in our [`fuzzers/binary_only/frida_libpng`](https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers/binary_only/frida_libpng) folder for Linux, and [`fuzzers/binary_only/frida_windows_gdiplus`](https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers/binary_only/frida_windows_gdiplus) for Windows.

## Dependencies

If you are on Linux or OSX, you'll need [libc++](https://libcxx.llvm.org/) for `libafl_frida` in addition to libafl's dependencies.
If you are on Windows, you'll need to install llvm tools.


## Harness & Instrumentation

LibAFL uses Frida's [__Stalker__](https://frida.re/docs/stalker/) to trace the execution of your program and instrument your harness.
Thus, you have to compile your harness to a dynamic library. Frida instruments your PUT after dynamically loading it.

In our `frida_libpng` example, we load the dynamic library and find the symbol to harness as follows:

```rust,ignore
        let lib = libloading::Library::new(module_name).unwrap();
        let target_func: libloading::Symbol<
            unsafe extern "C" fn(data: *const u8, size: usize) -> i32,
        > = lib.get(symbol_name.as_bytes()).unwrap();
```

## `FridaInstrumentationHelper` and Runtimes

To use functionalities that Frida offers, we'll first need to obtain a `Gum` object by `Gum::obtain()`.

In LibAFL, we use the `FridaInstrumentationHelper` struct to manage frida-related state. `FridaInstrumentationHelper` is a key component that sets up the [__Transformer__](https://frida.re/docs/stalker/#transformer) that is used to generate the instrumented code. It also initializes the `Runtimes` that offer various instrumentations.

We have `CoverageRuntime` that can track the edge coverage,  `AsanRuntime` for address sanitizer, `DrCovRuntime` that uses [__DrCov__](https://dynamorio.org/page_drcov.html) for coverage collection (to be imported in coverage tools like Lighthouse, bncov, dragondance,...), and `CmpLogRuntime` for cmplog instrumentation.
All of these runtimes can be slotted into `FridaInstrumentationHelper` at build time.

Combined with any `Runtime` you'd like to use, you can initialize the `FridaInstrumentationHelper` like this:

```rust,ignore

        let gum = Gum::obtain();
        let frida_options = FridaOptions::parse_env_options();
        let coverage = CoverageRuntime::new();
        let mut frida_helper = FridaInstrumentationHelper::new(
            &gum,
            &frida_options,
            module_name,
            modules_to_instrument,
            tuple_list!(coverage),
        );
```

## Running the Fuzzer

After setting up the `FridaInstrumentationHelper` you can obtain the pointer to the coverage map by calling `map_mut_ptr()`.

```rust,ignore
        let edges_observer = HitcountsMapObserver::new(StdMapObserver::from_mut_ptr(
            "edges",
            frida_helper.map_mut_ptr().unwrap(),
            MAP_SIZE,
        ));
```

You can then link this observer to `FridaInProcessExecutor` as follows:

```rust,ignore
        let mut executor = FridaInProcessExecutor::new(
            &gum,
            InProcessExecutor::new(
                &mut frida_harness,
                tuple_list!(
                    edges_observer,
                    time_observer,
                    AsanErrorsObserver::from_static_asan_errors()
                ),
                &mut fuzzer,
                &mut state,
                &mut mgr,
            )?,
            &mut frida_helper,
        );
```

And finally you can run the fuzzer.
See the `frida_` examples in [`./fuzzers/binary_only`](https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers/binary_only/) for more information and, for linux or full-system, play around with `libafl_qemu`, another binary_only tracer.
