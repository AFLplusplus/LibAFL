// this is required to be allowed to call the final executable what we want (and need) in Cargo.toml
#![allow(non_snake_case)]
#![forbid(unexpected_cfgs)]
//! Just a small runtime to be used in the smoke test.

use symcc_runtime::{
    export_runtime,
    filter::NoFloat,
    tracing::{self, StdShMemMessageFileWriter},
    Runtime,
};

export_runtime!(
    NoFloat => NoFloat;
    tracing::TracingRuntime::new(
        StdShMemMessageFileWriter::from_stdshmem_default_env()
            .expect("unable to construct tracing runtime writer. (missing env?)"),
        false
    )
    => tracing::TracingRuntime
);
