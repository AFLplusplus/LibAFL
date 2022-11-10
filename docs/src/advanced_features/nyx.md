# Snapshot Fuzzing in Nyx

NYX supports both source-based and binary-only fuzzing.

Currently, `libafl_nyx` only supports [afl++](https://github.com/AFLplusplus/AFLplusplus)'s instruction. To install it, you can use `sudo apt install aflplusplus`. Or compile from the source:

```bash
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make all # this will not compile afl's additional extension
```

Then you should compile the target with the afl++ compiler wrapper:

```bash
export CC=afl-clang-fast
export CXX=afl-clang-fast++
# the following line depends on your target
./configure --enable-shared=no
make
```

For binary-only fuzzing, Nyx uses intel-PT(Intel® Processor Trace). You can find the supported CPU at <https://www.intel.com/content/www/us/en/support/articles/000056730/processors.html>.

## Preparing Nyx working directory

This step is used to pack the target into Nyx's kernel. Don't worry, we have a template shell script in our [example](https://github.com/AFLplusplus/LibAFL/blob/main/fuzzers/nyx_libxml2_parallel/setup_libxml2.sh):

the parameter's meaning is listed below:

```bash
git clone https://github.com/nyx-fuzz/packer
python3 "./packer/packer/nyx_packer.py" \
    ./libxml2/xmllint \   # your target binary
    /tmp/nyx_libxml2 \    # the nyx work directory
    afl \                 # instruction type
    instrumentation \
    -args "/tmp/input" \  # the args of the program, means that we will run `xmllint /tmp/input` in each run.
    -file "/tmp/input" \  # the input will be generated in `/tmp/input`. If no `--file`, then input will be passed through stdin
    --fast_reload_mode \
    --purge || exit
```

Then, you can generate the config file:

```bash
python3 ./packer/packer/nyx_config_gen.py /tmp/nyx_libxml2/ Kernel || exit
```

## Standalone fuzzing

In the [example fuzzer](https://github.com/AFLplusplus/LibAFL/blob/main/fuzzers/nyx_libxml2_standalone/src/main.rs). First you need to run `./setup_libxml2.sh`, It will prepare your target and create your nyx work directory in `/tmp/libxml2`. After that, you can start write your code.

First, to create `Nyxhelper`:

```rust,ignore
let share_dir = Path::new("/tmp/nyx_libxml2/");
let cpu_id = 0; // use first cpu
let parallel_mode = false; // close parallel_mode
let mut helper = NyxHelper::new(share_dir, cpu_id, true, parallel_mode, None).unwrap(); // we don't the set the last parameter in standalone mode, we just use None, here
```

Then, fetch `trace_bits`, create an observer and the `NyxExecutor`:

```rust,ignore
let trace_bits = unsafe { std::slice::from_raw_parts_mut(helper.trace_bits, helper.map_size) };
let observer = StdMapObserver::new("trace", trace_bits);
let mut executor = NyxExecutor::new(&mut helper, tuple_list!(observer)).unwrap();
```

Finally, use them as normal and pass them into `fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)` to start fuzzing.

## Parallel fuzzing

In the [example fuzzer](https://github.com/AFLplusplus/LibAFL/blob/main/fuzzers/nyx_libxml2_parallel/src/main.rs). First you need to run `./setup_libxml2.sh` as described before.

Parallel fuzzing relies on [`Launcher`](../message_passing/spawn_instances.md), so spawn logic should be written in the scoop of anonymous function `run_client`:

```rust,ignore
let mut run_client = |state: Option<_>, mut restarting_mgr, _core_id: usize| {}
```

In `run_client`, you need to create `NyxHelper` first:

```rust,ignore
let share_dir = Path::new("/tmp/nyx_libxml2/");
let cpu_id = _core_id as u32;
let parallel_mode = true;
let mut helper = NyxHelper::new(
    share_dir, // nyx work directory
    cpu_id,    // current cpu id
    true,      // open snap_mode
    parallel_mode, // open parallel mode
    Some(parent_cpu_id.id as u32), // the cpu-id of master instance, there is only one master instance, other instances will be treated as slaved
)
.unwrap();
```

Then you can fetch the trace_bits and create an observer and `NyxExecutor`

```rust,ignore
let trace_bits =
    unsafe { std::slice::from_raw_parts_mut(helper.trace_bits, helper.map_size) };
let observer = StdMapObserver::new("trace", trace_bits);
let mut executor = NyxExecutor::new(&mut helper, tuple_list!(observer)).unwrap();
```

Finally, open a `Launcher` as normal to start fuzzing:

```rust,ignore
match Launcher::builder()
    .shmem_provider(shmem_provider)
    .configuration(EventConfig::from_name("default"))
    .monitor(monitor)
    .run_client(&mut run_client)
    .cores(&cores)
    .broker_port(broker_port)
    // .stdout_file(Some("/dev/null"))
    .build()
    .launch()
{
    Ok(()) => (),
    Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
    Err(err) => panic!("Failed to run launcher: {:?}", err),
}
```
