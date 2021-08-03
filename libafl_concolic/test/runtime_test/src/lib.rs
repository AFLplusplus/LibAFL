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
            .expect("unable to construct tracing runtime writer. (missing env?)")
        )
        => tracing::TracingRuntime
);
