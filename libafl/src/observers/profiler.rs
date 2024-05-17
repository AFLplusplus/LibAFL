//! This module will log every function that an execution has executed
//! In addition it will lookup from a database to profile what features are there in the executed path

use alloc::{borrow::Cow, vec::Vec};
use core::fmt::Debug;
use std::path::Path;
use alloc::string::String;

use libafl_bolts::{ownedref::OwnedMutPtr, Error, Named};
use serde::{Deserialize, Serialize};

use crate::{inputs::UsesInput, observers::Observer};

use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
struct AnalysisData {
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
    abc_metric: f64,
    cyclomatic: u32,
    #[serde(rename = "AP")]
    api_calls: HashMap<String, u32>,
    #[serde(rename = "h AP")]
    heap_apis: HashMap<String, u32>,
    #[serde(rename = "m AP")]
    memory_apis: HashMap<String, u32>,
    #[serde(rename = "ne lv")]
    nested_levels: HashMap<String, u32>,
    #[serde(rename = "cm gl")]
    cmp_globals: HashMap<String, u32>,
    #[serde(rename = "cm nz")]
    cmp_non_zeros: HashMap<String, u32>,
    #[serde(rename = "wr st")]
    struct_writes: HashMap<String, u32>,
    #[serde(rename = "str arg")]
    struct_args: HashMap<String, u32>,
    #[serde(rename = "cm ty")]
    cmp_types: HashMap<String, u32>,
    #[serde(rename = "cm cm")]
    cmp_complexity: HashMap<String, u32>,
    #[serde(rename = "ar ty")]
    call_arg_types: HashMap<String, u32>,
    #[serde(rename = "st ty")]
    store_types: HashMap<String, u32>,
    #[serde(rename = "l ty")]
    load_types: HashMap<String, u32>,
    #[serde(rename = "al ty")]
    alloca_types: HashMap<String, u32>,
}

/// A simple observer with a list of things.
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned + serde::Serialize")]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct ProfilerObserver<T> {
    name: Cow<'static, str>,
    /// The list
    list: OwnedMutPtr<Vec<T>>,
    // to do add map
}

impl<T> ProfilerObserver<T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`ProfilerObserver`] with the given name.
    ///
    /// # Safety
    /// Will dereference the list.
    /// The list may not move in memory.
    #[must_use]
    pub fn new<P>(name: &'static str, list: OwnedMutPtr<Vec<T>>, _json_path: P) -> Self
    where
        P: AsRef<Path>,
    {
        // todo; load json stuff
        Self {
            name: Cow::from(name),
            list,
        }
    }

    /// Get a list ref
    #[must_use]
    pub fn list(&self) -> &Vec<T> {
        self.list.as_ref()
    }

    /// Get a list mut
    #[must_use]
    pub fn list_mut(&mut self) -> &mut Vec<T> {
        self.list.as_mut()
    }

    // todo add the map getter/seter
}

impl<S, T> Observer<S> for ProfilerObserver<T>
where
    S: UsesInput,
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.list.as_mut().clear();
        Ok(())
    }
}

impl<T> Named for ProfilerObserver<T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}
