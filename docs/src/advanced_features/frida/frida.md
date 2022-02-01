# Binary-only Fuzzing with Frida
LibAFL supports binary-only fuzzing with Frida; the dynamic instrumentation tool.

In this section, we'll talk about some of the components in fuzzing with `libafl_frida`.
You can take a look at a working example in our `fuzzers/frida_libpng` folder.

# Dependencies
If you are on Linux, you'll need [libc++](https://libcxx.llvm.org/) for `libafl_frida` in addition to libafl's dependencies.
They can be installed with
`apt install libc++-12-dev libc++1-12 libc++abi-12-dev libc++abi1-12`


# Harness & Instrumentation
LibAFL uses Frida's [__Stalker__](https://frida.re/docs/stalker/) to trace the execution of your program and instrument your harness.
Thus you have to compile your harness to a dynamic library. Frida instruments your PUT after dynamically loading it.

For example in our `frida_libpng` example, we load the dynamic library and find the symbol to harness as follows:
```
        let lib = libloading::Library::new(module_name).unwrap();
        let target_func: libloading::Symbol<
            unsafe extern "C" fn(data: *const u8, size: usize) -> i32,
        > = lib.get(symbol_name.as_bytes()).unwrap();
```


# FridaInstrumentationHelper and Runtimes
To use functionalities that Frida offers, we'll first need to obtain `Gum` object by `Gum::obtain()`.

In LibAFL, We have `FridaInstrumentationHelper` to manage all the stuff related to Frida. `FridaInstrumentationHelper` is a key component that sets up the [__Transformer__](https://frida.re/docs/stalker/#transformer) that we use to generate the instrumented code. It also initializes the `Runtimes` that offers various instrumentation.

We have `CoverageRuntime` that has tracks the edge coverage,  `AsanRuntime` for address sanitizer, `DrCovRuntime` that uses [__DrCov__](https://dynamorio.org/page_drcov.html) for coverage collection, and `CmpLogRuntime` for cmplog instrumentation. All these runtimes can be used by slotting them into `FridaInstrumentationHelper`

Combined with any `Runtime` you'd like to use, you can initialize the `FridaInstrumentationHelpe`r like this:
```

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