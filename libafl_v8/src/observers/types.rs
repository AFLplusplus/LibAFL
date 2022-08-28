use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::{Debug, Formatter},
    hash::{Hash, Hasher},
    slice::Iter,
    sync::Arc,
};

use ahash::AHasher;
use deno_core::LocalInspectorSession;
use deno_runtime::worker::MainWorker;
use libafl::{
    bolts::{AsIter, AsMutSlice, HasLen},
    executors::ExitKind,
    observers::{MapObserver, Observer},
    prelude::Named,
    Error,
};
use serde::{Deserialize, Serialize};
use tokio::{runtime::Runtime, sync::Mutex};

use crate::{forbid_deserialization, observers::inspector_api::TakeTypeProfileReturnObject};

// while collisions are theoretically possible, the likelihood is vanishingly small
#[derive(Debug, Eq, Hash, PartialEq, Serialize, Deserialize, Clone)]
struct JSTypeEntry {
    script_hash: u64,
    offset: usize,
    name_hash: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct JSTypeMapper {
    idx_map: HashMap<JSTypeEntry, usize>,
}

impl JSTypeMapper {
    fn new() -> Self {
        Self {
            idx_map: HashMap::new(),
        }
    }

    fn process_coverage(&mut self, coverage: TakeTypeProfileReturnObject, map: &mut Vec<u8>) {
        let len: usize = coverage
            .result
            .iter()
            .flat_map(|stp| stp.entries.iter())
            .map(|entry| entry.types.len())
            .sum();

        // pre-allocate
        if map.capacity() < len {
            map.reserve(len - map.len());
        }

        coverage
            .result
            .into_iter()
            .flat_map(|stp| {
                let mut hasher = AHasher::default();
                stp.script_id.hash(&mut hasher);
                let script_hash = hasher.finish();
                stp.entries
                    .into_iter()
                    .map(move |entry| (script_hash, entry))
            })
            .flat_map(|(script_hash, entry)| {
                entry
                    .types
                    .into_iter()
                    .map(move |r#type| (script_hash, entry.offset, r#type.name))
            })
            .for_each(|(script_hash, offset, name)| {
                let mut hasher = AHasher::default();
                name.hash(&mut hasher);
                let name_hash = hasher.finish();
                let entry = JSTypeEntry {
                    script_hash,
                    offset,
                    name_hash,
                };
                match self.idx_map.entry(entry) {
                    Entry::Occupied(entry) => {
                        map[*entry.get()] = 1;
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(map.len());
                        map.push(1);
                    }
                }
            })
    }
}

/// Observer which inspects JavaScript type usage for parameters and return values
#[derive(Serialize, Deserialize)]
pub struct JSTypeObserver<'rt> {
    initial: u8,
    initialized: bool,
    last_coverage: Vec<u8>,
    name: String,
    mapper: JSTypeMapper,
    #[serde(skip, default = "forbid_deserialization")]
    rt: &'rt Runtime,
    #[serde(skip, default = "forbid_deserialization")]
    worker: Arc<Mutex<MainWorker>>,
    #[serde(skip, default = "forbid_deserialization")]
    inspector: Arc<Mutex<LocalInspectorSession>>,
}

impl<'rt> JSTypeObserver<'rt> {
    /// Create the observer with the provided name to use the provided asynchronous runtime, JS
    /// worker to push inspector data, and the parameters with which coverage is collected.
    pub fn new(
        name: &str,
        rt: &'rt Runtime,
        worker: Arc<Mutex<MainWorker>>,
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
            name: name.to_string(),
            mapper: JSTypeMapper::new(),
            rt,
            worker,
            inspector: Arc::new(Mutex::new(inspector)),
        })
    }
}

impl<'rt> Named for JSTypeObserver<'rt> {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<'rt> Debug for JSTypeObserver<'rt> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JSTypeObserver")
            .field("initialized", &self.initialized)
            .field("name", &self.name)
            .field("last_coverage", &self.last_coverage)
            .finish_non_exhaustive()
    }
}

impl<'rt, I, S> Observer<I, S> for JSTypeObserver<'rt> {
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.reset_map()?;
        if !self.initialized {
            let inspector = self.inspector.clone();
            let copy = self.worker.clone();
            self.rt.block_on(async {
                let mut locked = copy.lock().await;
                let mut session = inspector.lock().await;
                if let Err(e) = locked
                    .with_event_loop(Box::pin(
                        session.post_message::<()>("Profiler.startTypeProfile", None),
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

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        let session = self.inspector.clone();
        let copy = self.worker.clone();
        let coverage = self.rt.block_on(async {
            let mut locked = copy.lock().await;
            let mut session = session.lock().await;
            match locked
                .with_event_loop(Box::pin(
                    session.post_message::<()>("Profiler.takeTypeProfile", None),
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

impl<'rt> HasLen for JSTypeObserver<'rt> {
    fn len(&self) -> usize {
        self.last_coverage.len()
    }
}

impl<'rt, 'it> AsIter<'it> for JSTypeObserver<'rt> {
    type Item = u8;
    type IntoIter = Iter<'it, u8>;

    fn as_iter(&'it self) -> Self::IntoIter {
        self.last_coverage.as_slice().iter()
    }
}

impl<'rt> AsMutSlice<u8> for JSTypeObserver<'rt> {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.last_coverage.as_mut_slice()
    }
}

impl<'rt> MapObserver for JSTypeObserver<'rt> {
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
