//! The `CmpObserver` provides access to the logged values of CMP instructions

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    bolts::{ownedref::OwnedRefMut, tuples::Named},
    executors::HasExecHooks,
    observers::Observer,
    Error,
};

#[derive(Serialize, Deserialize)]
pub enum CmpValues {
    U8((u8, u8)),
    U16((u16, u16)),
    U32((u32, u32)),
    U64((u64, u64)),
    Bytes((Vec<u8>, Vec<u8>)),
}

/// A [`CmpMap`] traces comparisons during the current execution
pub trait CmpMap: Serialize + DeserializeOwned {
    /// Get the number of cmps
    fn len(&self) -> usize;

    fn executions_for(&self, idx: usize) -> usize;

    fn usable_executions_for(&self, idx: usize) -> usize;

    fn values_of(&self, idx: usize, execution: usize) -> CmpValues;

    /// Reset the state
    fn reset(&mut self) -> Result<(), Error>;
}

/// A [`CmpObserver`] observes the traced comparisons during the current execution using a [`CmpMap`]
pub trait CmpObserver<CM>: Observer
where
    CM: CmpMap,
{
    /// Get the number of usable cmps (all by default)
    fn usable_count(&self) -> usize;

    fn map(&self) -> &CM;

    fn map_mut(&mut self) -> &mut CM;
}

/// A standard [`CmpObserver`] observer
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "CM: serde::de::DeserializeOwned")]
pub struct StdCmpObserver<'a, CM>
where
    CM: CmpMap,
{
    map: OwnedRefMut<'a, CM>,
    size: Option<OwnedRefMut<'a, usize>>,
    name: String,
}

impl<'a, CM> CmpObserver<CM> for StdCmpObserver<'a, CM>
where
    CM: CmpMap,
{
    /// Get the number of usable cmps (all by default)
    fn usable_count(&self) -> usize {
        match &self.size {
            None => self.map().len(),
            Some(o) => *o.as_ref(),
        }
    }

    fn map(&self) -> &CM {
        self.map.as_ref()
    }

    fn map_mut(&mut self) -> &mut CM {
        self.map.as_mut()
    }
}

impl<'a, CM> Observer for StdCmpObserver<'a, CM> where CM: CmpMap {}

impl<'a, CM, EM, I, S, Z> HasExecHooks<EM, I, S, Z> for StdCmpObserver<'a, CM>
where
    CM: CmpMap,
{
    fn pre_exec(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) -> Result<(), Error> {
        self.map.as_mut().reset()?;
        Ok(())
    }
}

impl<'a, CM> Named for StdCmpObserver<'a, CM>
where
    CM: CmpMap,
{
    fn name(&self) -> &str {
        &self.name
    }
}

impl<'a, CM> StdCmpObserver<'a, CM>
where
    CM: CmpMap,
{
    /// Creates a new [`CmpObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str, map: &'a mut CM) -> Self {
        Self {
            name: name.to_string(),
            size: None,
            map: OwnedRefMut::Ref(map),
        }
    }

    // TODO with_size
}
