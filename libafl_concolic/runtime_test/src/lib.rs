use symcc_runtime::{export_runtime, filter::NoFloat, Runtime};

use symcc_runtime::tracing::{StdShMemMessageFileWriter, TracingRuntime};

export_runtime!(
    NoFloat => NoFloat;
    TracingRuntime::new(
        StdShMemMessageFileWriter::from_stdshmem_default_env()
            .expect("unable to construct tracing runtime writer. (missing env?)")
        )
        => TracingRuntime
);
