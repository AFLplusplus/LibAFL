use symcc_runtime::{
    export_runtime,
    filter::NoFloat,
    tracing::{self, StdShMemMessageFileWriter},
    Runtime,
};

//! This is a basic SymCC runtime.
//! It traces the execution to the shared memory region that should be passed through the environment by the fuzzer process. 
//! Additionally, it concretizes all floating point operations for simplicity.
//! Refer to the `symcc_runtime` crate documentation for building your own runtime.

export_runtime!(
    NoFloat => NoFloat;
    tracing::TracingRuntime::new(
        StdShMemMessageFileWriter::from_stdshmem_default_env()
            .expect("unable to construct tracing runtime writer. (missing env?)")
        )
        => tracing::TracingRuntime
);
