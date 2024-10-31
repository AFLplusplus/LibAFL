use alloc::{borrow::Cow, string::String};
use std::{fs::File, io::BufReader, path::Path};

use hashbrown::HashMap;
use libafl_bolts::{ownedref::OwnedMutPtr, Named};
use serde::{Deserialize, Serialize};

use crate::{observers::Observer, Error};
#[derive(Debug, Serialize, Deserialize)]
/// The json data
pub struct FunctionData {
    #[serde(rename = "name")]
    name: String,
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
    data: HashMap<usize, FunctionData>,
}

/// The observer to lookup the static analysis data at runtime
#[derive(Debug, Serialize, Deserialize)]
pub struct ProfilingObserver {
    /// The name of the observer.
    pub name: Cow<'static, str>,
    db: AnalysisData,
    /// The map
    map: OwnedMutPtr<HashMap<usize, usize>>,
}

impl ProfilingObserver {
    /// The constructor
    pub fn new<P>(json_path: P, map: OwnedMutPtr<HashMap<usize, usize>>) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let f = File::open(json_path.as_ref())?;
        let reader = BufReader::new(f);
        let analysis_data: AnalysisData = serde_json::from_reader(reader).map_err(|err| {
            let path = json_path.as_ref().to_string_lossy();
            Error::illegal_argument(format!("Failed to read from path {path}: {err:?}"))
        })?;
        // debug
        /*
        for record in &analysis_data.data {
            for (key, _value) in record.iter() {
                log::info!("Record {} found!", key);
            }
        }
        */

        Ok(Self {
            name: Cow::from("profiling"),
            db: analysis_data,
            map,
        })
    }

    /// Get the map
    #[must_use]
    pub fn map(&self) -> &HashMap<usize, usize> {
        self.map.as_ref()
    }

    /// lookup the data through db
    #[must_use]
    pub fn lookup(&self, function_id: usize) -> Option<&FunctionData> {
        let item = self.db.data.get(&function_id);
        item
    }
}

impl Named for ProfilingObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I, S> Observer<I, S> for ProfilingObserver {
    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &crate::executors::ExitKind,
    ) -> Result<(), Error> {
        // in reality, this should be done in a stage
        // but here just for poc
        for (key, _item) in self.map() {
            let found = self.lookup(*key);
            log::info!("key: {}, data: {:#?}", key, found);
        }
        log::info!("");
        Ok(())
    }
}
