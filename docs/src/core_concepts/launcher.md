# Launcher

Launcher is used to launch multiple fuzzer instances in parallel in one click. On `Unix` systems, Launcher will use `fork` if the `fork` feature is enabled. Else, it will start subsequent nodes with the same command line, and will set special `env` variables accordingly.

To use launcher, first you need to write an anonymous function `let mut run_client = |state: Option<_>, mut mgr, _core_id|{}`, which uses three parameters to create individual fuzzer. Then you can specify the `shmem_provider`,`broker_port`,`monitor`,`cores` and other stuff through `Launcher::builder()`:
1. To connect multiple nodes together via TCP, you can use the `remote_broker_addr`. this requires the `llmp_bind_public` compile-time feature for `LibAFL`.
2. To use multiple launchers for individual configurations, you can set `spawn_broker` to `false` on all but one.
3. Launcher will not select the cores automatically, so you need to specify the `cores` that you want.

For more examples, you can check out `qemu_launcher` and `libfuzzer_libpng_launcher` in `./fuzzers/`.