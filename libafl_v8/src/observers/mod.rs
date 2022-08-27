mod json_types;

use core::{
    fmt::{Debug, Formatter},
    slice::Iter,
};
use std::{
    borrow::BorrowMut,
    cell::RefCell,
    collections::{hash_map::Entry, HashMap},
    hash::{Hash, Hasher},
    rc::Rc,
    sync::{Arc, Mutex as StdMutex},
};

use ahash::{AHashMap, AHasher};
use deno_core::{
    futures::TryFutureExt, serde_json::Value, JsRuntime, JsRuntimeInspector, LocalInspectorSession,
};
use deno_runtime::worker::MainWorker;
use json_types::CoverageRange;
pub use json_types::{StartPreciseCoverageParameters, TakePreciseCoverageReturnObject};
use libafl::{
    bolts::{AsIter, AsMutSlice, HasLen},
    executors::ExitKind,
    observers::{MapObserver, Observer},
    prelude::Named,
    Error,
};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};
use tokio::{
    runtime::Runtime,
    sync::{oneshot::channel, Mutex},
};

use super::forbid_deserialization;

// while collisions are theoretically possible, the likelihood is vanishingly small
#[derive(Debug, Eq, Hash, PartialEq, Serialize, Deserialize, Clone)]
struct JSCoverageEntry {
    script_hash: u64,
    function_hash: u64,
    start_char_offset: usize,
    end_char_offset: usize,
}

#[derive(Serialize, Deserialize, Default)]
struct JSCoverageMapper {
    count: bool,
    idx_map: HashMap<JSCoverageEntry, usize>,
}

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

#[derive(Serialize, Deserialize)]
pub struct JSMapObserver<'rt> {
    initial: u8,
    initialized: bool,
    last_coverage: Vec<u8>,
    mapper: JSCoverageMapper,
    name: String,
    params: StartPreciseCoverageParameters,
    #[serde(skip, default = "forbid_deserialization")]
    rt: &'rt Runtime,
    #[serde(skip, default = "forbid_deserialization")]
    worker: Arc<Mutex<MainWorker>>,
    #[serde(skip, default = "forbid_deserialization")]
    inspector: Arc<Mutex<LocalInspectorSession>>,
}

impl<'rt> JSMapObserver<'rt> {
    pub fn new(
        name: &str,
        rt: &'rt Runtime,
        worker: Arc<Mutex<MainWorker>>,
    ) -> Result<Self, Error> {
        Self::new_with_parameters(
            name,
            rt,
            worker,
            StartPreciseCoverageParameters {
                call_count: true,
                detailed: true,
                allow_triggered_updates: false,
            },
        )
    }

    pub fn new_with_parameters(
        name: &str,
        rt: &'rt Runtime,
        worker: Arc<Mutex<MainWorker>>,
        params: StartPreciseCoverageParameters,
    ) -> Result<Self, Error> {
        let inspector = {
            let copy = worker.clone();
            rt.block_on(async {
                let mut locked = copy.lock().await;
                let mut session = locked.create_inspector_session().await;
                if let Err(e) = locked
                    .with_event_loop(Box::pin(
                        session.post_message::<()>("Profiler.enable", None),
                    ))
                    .await
                {
                    Err(Error::unknown(e.to_string()))
                } else {
                    Ok(session)
                }
            })?
        };
        Ok(Self {
            initial: u8::default(),
            initialized: false,
            last_coverage: Vec::new(),
            mapper: JSCoverageMapper::new(params.call_count),
            name: name.to_string(),
            params,
            rt,
            worker,
            inspector: Arc::new(Mutex::new(inspector)),
        })
    }
}

impl<'rt> Named for JSMapObserver<'rt> {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<'rt> Debug for JSMapObserver<'rt> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JSMapObserver")
            .field("initialized", &self.initialized)
            .field("name", &self.name)
            .field("last_coverage", &self.last_coverage)
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

impl<'rt, I, S> Observer<I, S> for JSMapObserver<'rt> {
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.reset_map()?;
        if !self.initialized {
            let inspector = self.inspector.clone();
            let params = self.params.clone();
            let copy = self.worker.clone();
            self.rt.block_on(async {
                let mut locked = copy.lock().await;
                let mut session = inspector.lock().await;
                if let Err(e) = locked
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

    fn post_exec(&mut self, _state: &mut S, _input: &I, exit_kind: &ExitKind) -> Result<(), Error> {
        let session = self.inspector.clone();
        let copy = self.worker.clone();
        let coverage = self.rt.block_on(async {
            let mut locked = copy.lock().await;
            let mut session = session.lock().await;
            match locked
                .with_event_loop(Box::pin(
                    session.post_message::<()>("Profiler.takePreciseCoverage", None),
                ))
                .await
            {
                Ok(value) => Ok(serde_json::from_value(value)?),
                Err(e) => return Err(Error::unknown(e.to_string())),
            }
        })?;
        self.mapper
            .process_coverage(coverage, &mut self.last_coverage);
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

impl<'rt> HasLen for JSMapObserver<'rt> {
    fn len(&self) -> usize {
        self.last_coverage.len()
    }
}

impl<'rt, 'it> AsIter<'it> for JSMapObserver<'rt> {
    type Item = u8;
    type IntoIter = Iter<'it, u8>;

    fn as_iter(&'it self) -> Self::IntoIter {
        self.last_coverage.as_slice().iter()
    }
}

impl<'rt> AsMutSlice<u8> for JSMapObserver<'rt> {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.last_coverage.as_mut_slice()
    }
}

impl<'rt> MapObserver for JSMapObserver<'rt> {
    type Entry = u8;

    fn get(&self, idx: usize) -> &Self::Entry {
        &self.last_coverage[idx]
    }

    fn get_mut(&mut self, idx: usize) -> &mut Self::Entry {
        &mut self.last_coverage[idx]
    }

    fn usable_count(&self) -> usize {
        self.last_coverage.len()
    }

    fn count_bytes(&self) -> u64 {
        self.last_coverage.iter().filter(|&&e| e != 0).count() as u64
    }

    fn hash(&self) -> u64 {
        let mut hasher = AHasher::default();
        self.last_coverage.hash(&mut hasher);
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
        let map = self.last_coverage.as_mut_slice();
        for x in map[0..cnt].iter_mut() {
            *x = initial;
        }
        Ok(())
    }

    fn to_vec(&self) -> Vec<Self::Entry> {
        self.last_coverage.clone()
    }

    fn how_many_set(&self, indexes: &[usize]) -> usize {
        let initial = self.initial();
        let cnt = self.usable_count();
        let map = self.last_coverage.as_slice();
        let mut res = 0;
        for i in indexes {
            if *i < cnt && map[*i] != initial {
                res += 1;
            }
        }
        res
    }
}
