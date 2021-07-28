use symcc_runtime::{export_runtime, filter::NoFloat, NopRuntime, Runtime};

export_runtime!( NoFloat => NoFloat ; NopRuntime => NopRuntime);
