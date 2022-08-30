use core::{
    fmt::{Debug, Formatter},
    slice::Iter,
};
use std::{
    collections::{hash_map::Entry, HashMap},
    hash::{Hash, Hasher},
    sync::Arc,
};

use ahash::AHasher;
use deno_core::LocalInspectorSession;
use libafl::{
    bolts::{AsIter, AsMutSlice, HasLen},
    executors::ExitKind,
    observers::{MapObserver, Observer},
    prelude::Named,
    state::HasMetadata,
    Error,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

pub use super::inspector_api::StartPreciseCoverageParameters;
use super::inspector_api::TakePreciseCoverageReturnObject;
use crate::{create_inspector, RUNTIME, WORKER};

// while collisions are theoretically possible, the likelihood is vanishingly small
#[derive(Debug, Eq, Hash, PartialEq, Serialize, Deserialize, Clone)]
struct JSCoverageEntry {
    script_hash: u64,
    function_hash: u64,
    start_char_offset: usize,
    end_char_offset: usize,
}

#[derive(Serialize, Deserialize, Default, Debug)]
struct JSCoverageMapper {
    count: bool,
    idx_map: HashMap<JSCoverageEntry, usize>,
}

libafl::impl_serdeany!(JSCoverageMapper);

impl JSCoverageMapper {
    fn new(count: bool) -> Self {
        Self {
            count,
            idx_map: HashMap::new(),
        }
    }

    fn process_coverage(&mut self, coverage: TakePreciseCoverageReturnObject, map: &mut Vec<u8>) {
        let len: usize = coverage
            .result
            .iter()
            .flat_map(|scov| scov.functions.iter())
            .map(|fcov| fcov.ranges.len())
            .sum();

        // pre-allocate
        if map.capacity() < len {
            map.reserve(len - map.len());
        }

        let count_computer = if self.count {
            |count| match count {
                count if count <= 0 => 0,
                count if count > 255 => 255,
                count => count as u8,
            }
        } else {
            |count| match count {
                0 => 0,
                _ => 1,
            }
        };
        coverage
            .result
            .into_iter()
            .flat_map(|scov| {
                let mut hasher = AHasher::default();
                scov.script_id.hash(&mut hasher);
                let script_hash = hasher.finish();
                scov.functions
                    .into_iter()
                    .map(move |fcov| (script_hash, fcov))
            })
            .flat_map(|(script_hash, fcov)| {
                let mut hasher = AHasher::default();
                fcov.function_name.hash(&mut hasher);
                let function_hash = hasher.finish();
                fcov.ranges
                    .into_iter()
                    .map(move |rcov| (script_hash, function_hash, rcov))
            })
            .for_each(|(script_hash, function_hash, rcov)| {
                let entry = JSCoverageEntry {
                    script_hash,
                    function_hash,
                    start_char_offset: rcov.start_char_offset,
                    end_char_offset: rcov.end_char_offset,
                };
                let count_computed = count_computer(rcov.count);
                match self.idx_map.entry(entry) {
                    Entry::Occupied(entry) => {
                        map[*entry.get()] = count_computed;
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(map.len());
                        map.push(count_computed);
                    }
                }
            })
    }
}

/// Observer which inspects JavaScript coverage at either a block or function level
///
/// This observer must not have its contents reused by other fuzzer instances; use
/// EventConfig::AlwaysUnique or *this will crash*.
#[derive(Serialize, Deserialize)]
pub struct JSMapObserver {
    initial: u8,
    initialized: bool,
    #[serde(skip, default)]
    last_coverage: Option<Vec<u8>>,
    name: String,
    params: StartPreciseCoverageParameters,
    #[serde(skip, default)]
    inspector: Option<Arc<Mutex<LocalInspectorSession>>>,
}

impl JSMapObserver {
    /// Create the observer with the provided name to use the provided asynchronous runtime and JS
    /// worker to push inspector data. If you don't know what kind of coverage you want, use this
    /// constructor.
    pub fn new(name: &str) -> Result<Self, Error> {
        Self::new_with_parameters(
            name,
            StartPreciseCoverageParameters {
                call_count: true,
                detailed: true,
                allow_triggered_updates: false,
            },
        )
    }

    /// Create the observer with the provided name to use the provided asynchronous runtime, JS
    /// worker to push inspector data, and the parameters with which coverage is collected.
    pub fn new_with_parameters(
        name: &str,
        params: StartPreciseCoverageParameters,
    ) -> Result<Self, Error> {
        Ok(Self {
            initial: u8::default(),
            initialized: false,
            last_coverage: Some(Vec::new()),
            name: name.to_string(),
            params,
            inspector: Some(create_inspector()),
        })
    }
}

impl Named for JSMapObserver {
    fn name(&self) -> &str {
        &self.name
    }
}

impl Debug for JSMapObserver {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JSMapObserver")
            .field("initialized", &self.initialized)
            .field("name", &self.name)
            .field("last_coverage", &self.last_coverage)
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

impl<I, S> Observer<I, S> for JSMapObserver
where
    S: HasMetadata,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.reset_map()?;
        if !self.initialized {
            let inspector = self.inspector.as_ref().unwrap().clone();
            let params = self.params.clone();
            unsafe { RUNTIME.as_ref() }.unwrap().block_on(async {
                let worker = unsafe { WORKER.as_mut() }.unwrap();
                let mut session = inspector.lock().await;
                if let Err(e) = worker
                    .with_event_loop(Box::pin(
                        session.post_message("Profiler.startPreciseCoverage", Some(&params)),
                    ))
                    .await
                {
                    Err(Error::unknown(e.to_string()))
                } else {
                    Ok(())
                }
            })?;
            self.initialized = true;
        }
        Ok(())
    }

    fn post_exec(&mut self, state: &mut S, _input: &I, _exit_kind: &ExitKind) -> Result<(), Error> {
        let session = self.inspector.as_ref().unwrap().clone();
        let coverage = unsafe { RUNTIME.as_ref() }.unwrap().block_on(async {
            let worker = unsafe { WORKER.as_mut() }.unwrap();
            let mut session = session.lock().await;
            match worker
                .with_event_loop(Box::pin(
                    session.post_message::<()>("Profiler.takePreciseCoverage", None),
                ))
                .await
            {
                Ok(value) => Ok(serde_json::from_value(value)?),
                Err(e) => return Err(Error::unknown(e.to_string())),
            }
        })?;
        let mapper = if let Some(mapper) = state.metadata_mut().get_mut::<JSCoverageMapper>() {
            mapper
        } else {
            state
                .metadata_mut()
                .insert::<JSCoverageMapper>(JSCoverageMapper::new(self.params.call_count));
            state.metadata_mut().get_mut::<JSCoverageMapper>().unwrap()
        };
        mapper.process_coverage(coverage, self.last_coverage.as_mut().unwrap());
        Ok(())
    }

    fn pre_exec_child(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Err(Error::unsupported("Cannot be used in a forking context"))
    }

    fn post_exec_child(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Err(Error::unsupported("Cannot be used in a forking context"))
    }
}

impl HasLen for JSMapObserver {
    fn len(&self) -> usize {
        self.last_coverage.as_ref().unwrap().len()
    }
}

impl<'it> AsIter<'it> for JSMapObserver {
    type Item = u8;
    type IntoIter = Iter<'it, u8>;

    fn as_iter(&'it self) -> Self::IntoIter {
        self.last_coverage.as_ref().unwrap().as_slice().iter()
    }
}

impl AsMutSlice<u8> for JSMapObserver {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.last_coverage.as_mut().unwrap().as_mut_slice()
    }
}

impl MapObserver for JSMapObserver {
    type Entry = u8;

    fn get(&self, idx: usize) -> &Self::Entry {
        &self.last_coverage.as_ref().unwrap()[idx]
    }

    fn get_mut(&mut self, idx: usize) -> &mut Self::Entry {
        &mut self.last_coverage.as_mut().unwrap()[idx]
    }

    fn usable_count(&self) -> usize {
        self.last_coverage.as_ref().unwrap().len()
    }

    fn count_bytes(&self) -> u64 {
        self.last_coverage
            .as_ref()
            .unwrap()
            .iter()
            .filter(|&&e| e != 0)
            .count() as u64
    }

    fn hash(&self) -> u64 {
        let mut hasher = AHasher::default();
        self.last_coverage.as_ref().unwrap().hash(&mut hasher);
        hasher.finish()
    }

    fn initial(&self) -> Self::Entry {
        self.initial
    }

    fn initial_mut(&mut self) -> &mut Self::Entry {
        &mut self.initial
    }

    fn reset_map(&mut self) -> Result<(), Error> {
        let initial = self.initial();
        let cnt = self.usable_count();
        let map = self.last_coverage.as_mut().unwrap().as_mut_slice();
        for x in map[0..cnt].iter_mut() {
            *x = initial;
        }
        Ok(())
    }

    fn to_vec(&self) -> Vec<Self::Entry> {
        self.last_coverage.as_ref().unwrap().clone()
    }

    fn how_many_set(&self, indexes: &[usize]) -> usize {
        let initial = self.initial();
        let cnt = self.usable_count();
        let map = self.last_coverage.as_ref().unwrap().as_slice();
        let mut res = 0;
        for i in indexes {
            if *i < cnt && map[*i] != initial {
                res += 1;
            }
        }
        res
    }
}
