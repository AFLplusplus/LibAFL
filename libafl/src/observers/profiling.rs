use alloc::{string::String, vec::Vec};
use std::{collections::HashMap, fs::File, io::BufReader, path::Path};

use serde::{Deserialize, Serialize};

use crate::Error;

#[derive(Debug, Serialize, Deserialize)]
struct FunctionData {
    #[serde(rename = "ID")]
    id: usize,
    #[serde(rename = "# BBs")]
    bb_count: Option<u32>,
    #[serde(rename = "# insts")]
    inst_count: Option<u32>,
    #[serde(rename = "# edges")]
    edge_count: Option<u32>,
    #[serde(rename = "# binaryOp")]
    binary_op_count: Option<u32>,
    #[serde(rename = "# call")]
    call_count: Option<u32>,
    #[serde(rename = "# cmp")]
    cmp_count: Option<u32>,
    #[serde(rename = "# load")]
    load_count: Option<u32>,
    #[serde(rename = "# store")]
    store_count: Option<u32>,
    #[serde(rename = "# alloca")]
    alloca_count: Option<u32>,
    #[serde(rename = "# branch")]
    branch_count: Option<u32>,
    #[serde(rename = "ABC metric")]
    abc_metric: Option<f64>,
    cyclomatic: Option<u32>,
    #[serde(rename = "AP")]
    api_calls: Option<HashMap<String, u32>>,
    #[serde(rename = "h AP")]
    heap_apis: Option<HashMap<String, u32>>,
    #[serde(rename = "m AP")]
    memory_apis: Option<HashMap<String, u32>>,
    #[serde(rename = "ne lv")]
    nested_level: Option<HashMap<String, u32>>,
    #[serde(rename = "cm gl")]
    cmp_globals: Option<HashMap<String, u32>>,
    #[serde(rename = "cm nz")]
    cmp_non_zeros: Option<HashMap<String, u32>>,
    #[serde(rename = "wr st")]
    struct_writes: Option<HashMap<String, u32>>,
    #[serde(rename = "str arg")]
    struct_args: Option<HashMap<String, u32>>,
    #[serde(rename = "cm ty")]
    cmp_types: Option<HashMap<String, u32>>,
    #[serde(rename = "cm cm")]
    cmp_complexity: Option<HashMap<String, u32>>,
    #[serde(rename = "ar ty")]
    call_arg_types: Option<HashMap<String, u32>>,
    #[serde(rename = "st ty")]
    store_types: Option<HashMap<String, u32>>,
    #[serde(rename = "l ty")]
    load_types: Option<HashMap<String, u32>>,
    #[serde(rename = "al ty")]
    alloca_types: Option<HashMap<String, u32>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct AnalysisData {
    data: Vec<HashMap<String, FunctionData>>,
}

/// The observer to lookup the static analysis data at runtime
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ProfilingObserver {
    data: AnalysisData,
}

impl ProfilingObserver {
    /// The constructor
    pub fn new<P>(json_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let f = File::open(json_path)?;
        let reader = BufReader::new(f);
        let analysis_data: AnalysisData = serde_json::from_reader(reader)?;

        Ok(Self {
            data: analysis_data,
        })
    }
}
