//! The `CmpObserver` provides access to the logged values of CMP instructions

use alloc::string::{String, ToString};
use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

use libafl_bolts::{ownedref::OwnedRefMut, Named};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    executors::ExitKind,
    inputs::UsesInput,
    observers::{
        cmp::{
            CmpLogHeader, CmpMap, CmpObserver, CmpObserverMetadata, CmpValues, CmpValuesMetadata,
            CMPLOG_KIND_INS,
        },
        Observer,
    },
    state::HasMetadata,
    Error,
};

/// The width of cmplog map
pub const CMPLOG_MAP_W: usize = 65536;

/// The height (history len) of cmplog map
pub const CMPLOG_MAP_H: usize = 32;
/// The `CmpLog` map size
pub const CMPLOG_MAP_SIZE: usize = CMPLOG_MAP_W * CMPLOG_MAP_H;

/// The size of a logged routine argument in bytes
pub const CMPLOG_RTN_LEN: usize = 32;

/// The hight of a cmplog routine map
pub const CMPLOG_MAP_RTN_H: usize = (CMPLOG_MAP_H * core::mem::size_of::<CmpLogInstruction>())
    / core::mem::size_of::<CmpLogRoutine>();

/// The operands logged during `CmpLog`.
#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct CmpLogInstruction(pub u64, pub u64);

/// The routine arguments logged during `CmpLog`.
#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct CmpLogRoutine([u8; CMPLOG_RTN_LEN], [u8; CMPLOG_RTN_LEN]);

/// Union of cmplog operands and routines
#[repr(C)]
#[derive(Clone, Copy)]
pub union CmpLogVals {
    /// instruction operands
    pub operands: [[CmpLogInstruction; CMPLOG_MAP_H]; CMPLOG_MAP_W],
    /// routine operands
    pub routines: [[CmpLogRoutine; CMPLOG_MAP_RTN_H]; CMPLOG_MAP_W],
}

impl Debug for CmpLogVals {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CmpLogVals").finish_non_exhaustive()
    }
}

/// A struct containing the `CmpLog` metadata for a `LibAFL` run.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CmpLogMap {
    pub headers: [CmpLogHeader; CMPLOG_MAP_W],
    pub vals: CmpLogVals,
}

impl Default for CmpLogMap {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

impl CmpMap for CmpLogMap {
    fn len(&self) -> usize {
        CMPLOG_MAP_W
    }

    fn executions_for(&self, idx: usize) -> usize {
        self.headers[idx].hits as usize
    }

    fn usable_executions_for(&self, idx: usize) -> usize {
        if self.headers[idx].kind == CMPLOG_KIND_INS {
            if self.executions_for(idx) < CMPLOG_MAP_H {
                self.executions_for(idx)
            } else {
                CMPLOG_MAP_H
            }
        } else if self.executions_for(idx) < CMPLOG_MAP_RTN_H {
            self.executions_for(idx)
        } else {
            CMPLOG_MAP_RTN_H
        }
    }

    fn values_of(&self, idx: usize, execution: usize) -> Option<CmpValues> {
        if self.headers[idx].kind == CMPLOG_KIND_INS {
            unsafe {
                match self.headers[idx].shape {
                    0 => Some(CmpValues::U8((
                        self.vals.operands[idx][execution].0 as u8,
                        self.vals.operands[idx][execution].1 as u8,
                    ))),
                    1 => Some(CmpValues::U16((
                        self.vals.operands[idx][execution].0 as u16,
                        self.vals.operands[idx][execution].1 as u16,
                    ))),
                    3 => Some(CmpValues::U32((
                        self.vals.operands[idx][execution].0 as u32,
                        self.vals.operands[idx][execution].1 as u32,
                    ))),
                    7 => Some(CmpValues::U64((
                        self.vals.operands[idx][execution].0,
                        self.vals.operands[idx][execution].1,
                    ))),
                    // other => panic!("Invalid CmpLog shape {}", other),
                    _ => None,
                }
            }
        } else {
            unsafe {
                Some(CmpValues::Bytes((
                    self.vals.routines[idx][execution].0.to_vec(),
                    self.vals.routines[idx][execution].1.to_vec(),
                )))
            }
        }
    }

    fn reset(&mut self) -> Result<(), Error> {
        // For performance, we reset just the headers
        self.headers.fill(CmpLogHeader {
            hits: 0,
            shape: 0,
            kind: 0,
        });

        Ok(())
    }
}

/// A standard [`CmpObserver`] observer
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "CM: serde::de::DeserializeOwned")]
pub struct StdCmpObserver<'a, CM, S, M>
where
    CM: CmpMap + Serialize,
    S: UsesInput + HasMetadata,
    M: CmpObserverMetadata<'a, CM>,
{
    cmp_map: OwnedRefMut<'a, CM>,
    size: Option<OwnedRefMut<'a, usize>>,
    name: String,
    add_meta: bool,
    data: M::Data,
    phantom: PhantomData<S>,
}

impl<'a, CM, S, M> CmpObserver<'a, CM, S, M> for StdCmpObserver<'a, CM, S, M>
where
    CM: CmpMap + Serialize + DeserializeOwned,
    S: UsesInput + Debug + HasMetadata,
    M: CmpObserverMetadata<'a, CM>,
{
    /// Get the number of usable cmps (all by default)
    fn usable_count(&self) -> usize {
        match &self.size {
            None => self.cmp_map.as_ref().len(),
            Some(o) => *o.as_ref(),
        }
    }

    fn cmp_map(&self) -> &CM {
        self.cmp_map.as_ref()
    }

    fn cmp_map_mut(&mut self) -> &mut CM {
        self.cmp_map.as_mut()
    }

    fn cmp_observer_data(&self) -> <M as CmpObserverMetadata<'a, CM>>::Data {
        <M as CmpObserverMetadata<CM>>::Data::default()
    }
}

impl<'a, CM, S, M> Observer<S> for StdCmpObserver<'a, CM, S, M>
where
    CM: CmpMap + Serialize + DeserializeOwned,
    S: UsesInput + Debug + HasMetadata,
    M: CmpObserverMetadata<'a, CM>,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.cmp_map.as_mut().reset()?;
        Ok(())
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        if self.add_meta {
            self.add_cmpvalues_meta(state);
        }
        Ok(())
    }
}

impl<'a, CM, S, M> Named for StdCmpObserver<'a, CM, S, M>
where
    CM: CmpMap + Serialize + DeserializeOwned,
    S: UsesInput + HasMetadata,
    M: CmpObserverMetadata<'a, CM>,
{
    fn name(&self) -> &str {
        &self.name
    }
}

impl<'a, CM, S, M> StdCmpObserver<'a, CM, S, M>
where
    CM: CmpMap + Serialize + DeserializeOwned,
    S: UsesInput + HasMetadata,
    M: CmpObserverMetadata<'a, CM>,
{
    /// Creates a new [`StdCmpObserver`] with the given name and map.
    #[must_use]
    pub fn new(name: &'static str, map: &'a mut CM, add_meta: bool) -> Self {
        Self {
            name: name.to_string(),
            size: None,
            cmp_map: OwnedRefMut::Ref(map),
            add_meta,
            data: M::Data::default(),
            phantom: PhantomData,
        }
    }

    /// Creates a new [`StdCmpObserver`] with the given name, map, and auxiliary data used to
    /// populate metadata
    #[must_use]
    pub fn with_data(name: &'static str, map: &'a mut CM, add_meta: bool, data: M::Data) -> Self {
        Self {
            name: name.to_string(),
            size: None,
            cmp_map: OwnedRefMut::Ref(map),
            add_meta,
            data,
            phantom: PhantomData,
        }
    }

    /// Creates a new [`StdCmpObserver`] with the given name, map and reference to variable size.
    #[must_use]
    pub fn with_size(
        name: &'static str,
        map: &'a mut CM,
        add_meta: bool,
        size: &'a mut usize,
    ) -> Self {
        Self {
            name: name.to_string(),
            size: Some(OwnedRefMut::Ref(size)),
            cmp_map: OwnedRefMut::Ref(map),
            add_meta,
            data: M::Data::default(),
            phantom: PhantomData,
        }
    }

    /// Creates a new [`StdCmpObserver`] with the given name, map, auxiliary data, and
    /// reference to variable size.
    #[must_use]
    pub fn with_size_data(
        name: &'static str,
        map: &'a mut CM,
        add_meta: bool,
        data: M::Data,
        size: &'a mut usize,
    ) -> Self {
        Self {
            name: name.to_string(),
            size: Some(OwnedRefMut::Ref(size)),
            cmp_map: OwnedRefMut::Ref(map),
            add_meta,
            data,
            phantom: PhantomData,
        }
    }

    /// Reference the stored auxiliary data associated with the [`CmpObserverMetadata`]
    pub fn data(&self) -> &M::Data {
        &self.data
    }

    /// Mutably reference the stored auxiliary data associated with the [`CmpObserverMetadata`]
    pub fn data_mut(&mut self) -> &mut M::Data {
        &mut self.data
    }
}

/// A [`StdCmpObserver`] that optionally adds comparisons into a [`CmpValuesMetadata`]
pub type StdCmpValuesObserver<'a, CM, S> = StdCmpObserver<'a, CM, S, CmpValuesMetadata>;
