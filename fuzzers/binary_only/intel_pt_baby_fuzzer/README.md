# Baby fuzzer with Intel PT tracing

This is a minimalistic example about how to create a libafl based fuzzer with Intel PT tracing.

It runs on a single core until a crash occurs and then exits.

The tested program is a simple Rust function without any instrumentation.

On `Linux`, after building this example with `cargo build`, you need to give to the executable the necessary
capabilities with
`sudo setcap cap_ipc_lock,cap_sys_ptrace,cap_sys_admin,cap_syslog=ep ./target/debug/intel_pt_baby_fuzzer`.
You can then run this example using `cargo run`.

As an alternative, simply run `just` to build and run the fuzzer (requires `just`).

On `Windows`, make sure the `ipt` service is running (`sc start ipt` from an admin shell), then run this example with
`cargo run`, or simply `just` to build and run it.

This fuzzer is compatible with `Linux` and `Windows` hosts having an Intel PT compatible CPU.
