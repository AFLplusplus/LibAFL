use symcc_runtime::{export_runtime, filter, tracing, Runtime};

export_runtime!(
    filter::NoFloat => filter::NoFloat;
    tracing::TracingRuntime::new(
        tracing::StdShMemMessageFileWriter::from_stdshmem_default_env()
            .expect("unable to construct tracing runtime writer. (missing env?)")
        )
        => tracing::TracingRuntime
);
