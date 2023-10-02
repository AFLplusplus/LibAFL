use alloc::vec::Vec;
use core::fmt::Debug;

use libafl_bolts::{serdeany::SerdeAny, AsMutSlice, AsSlice};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{inputs::UsesInput, observers::Observer, state::HasMetadata, Error};

pub mod aflppcmp;
pub mod cmp;

/// `CmpLog` instruction kind
pub const CMPLOG_KIND_INS: u8 = 0;
/// `CmpLog` routine kind
pub const CMPLOG_KIND_RTN: u8 = 1;

/// Generic metadata trait for use in a `CmpObserver`, which adds comparisons from a `CmpObserver`
/// primarily intended for use with `AFLppCmpValuesMetadata` or `CmpValuesMetadata`
pub trait CmpObserverMetadata<'a, CM>: SerdeAny + Debug
where
    CM: CmpMap + Debug,
{
    /// Extra data used by the metadata when adding information from a `CmpObserver`, for example
    /// the `original` field in `AFLppCmpObserver`
    type Data: 'a + Debug + Default + Serialize + DeserializeOwned;

    /// Instantiate a new metadata instance. This is used by `CmpObserver` to create a new
    /// metadata if one is missing and `add_meta` is specified. This will typically juse call
    /// `new()`
    fn new_metadata() -> Self;

    /// Add comparisons to a metadata from a `CmpObserver`. `cmp_map` is mutable in case
    /// it is needed for a custom map, but this is not utilized for `CmpObserver` or
    /// `AFLppCmpObserver`.
    fn add_from(&mut self, usable_count: usize, cmp_map: &mut CM, cmp_observer_data: Self::Data);
}

/// A state metadata holding a list of values logged from comparisons
#[derive(Debug, Default, Serialize, Deserialize)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct CmpValuesMetadata {
    /// A `list` of values.
    #[serde(skip)]
    pub list: Vec<CmpValues>,
}
libafl_bolts::impl_serdeany!(CmpValuesMetadata);

/// Compare values collected during a run
#[derive(Eq, PartialEq, Debug, Serialize, Deserialize, Clone)]
pub enum CmpValues {
    /// Two u8 values
    U8((u8, u8)),
    /// Two u16 values
    U16((u16, u16)),
    /// Two u32 values
    U32((u32, u32)),
    /// Two u64 values
    U64((u64, u64)),
    /// Two vecs of u8 values/byte
    Bytes((Vec<u8>, Vec<u8>)),
}

impl CmpValues {
    /// Returns if the values are numericals
    #[must_use]
    pub fn is_numeric(&self) -> bool {
        matches!(
            self,
            CmpValues::U8(_) | CmpValues::U16(_) | CmpValues::U32(_) | CmpValues::U64(_)
        )
    }

    /// Converts the value to a u64 tuple
    #[must_use]
    pub fn to_u64_tuple(&self) -> Option<(u64, u64)> {
        match self {
            CmpValues::U8(t) => Some((u64::from(t.0), u64::from(t.1))),
            CmpValues::U16(t) => Some((u64::from(t.0), u64::from(t.1))),
            CmpValues::U32(t) => Some((u64::from(t.0), u64::from(t.1))),
            CmpValues::U64(t) => Some(*t),
            CmpValues::Bytes(_) => None,
        }
    }
}

impl<'a, CM> CmpObserverMetadata<'a, CM> for CmpValuesMetadata
where
    CM: CmpMap,
{
    type Data = bool;

    #[must_use]
    fn new_metadata() -> Self {
        Self::new()
    }

    fn add_from(&mut self, usable_count: usize, cmp_map: &mut CM, _: Self::Data) {
        self.list.clear();
        let count = usable_count;
        for i in 0..count {
            let execs = cmp_map.usable_executions_for(i);
            if execs > 0 {
                // Recongize loops and discard if needed
                if execs > 4 {
                    let mut increasing_v0 = 0;
                    let mut increasing_v1 = 0;
                    let mut decreasing_v0 = 0;
                    let mut decreasing_v1 = 0;

                    let mut last: Option<CmpValues> = None;
                    for j in 0..execs {
                        if let Some(val) = cmp_map.values_of(i, j) {
                            if let Some(l) = last.and_then(|x| x.to_u64_tuple()) {
                                if let Some(v) = val.to_u64_tuple() {
                                    if l.0.wrapping_add(1) == v.0 {
                                        increasing_v0 += 1;
                                    }
                                    if l.1.wrapping_add(1) == v.1 {
                                        increasing_v1 += 1;
                                    }
                                    if l.0.wrapping_sub(1) == v.0 {
                                        decreasing_v0 += 1;
                                    }
                                    if l.1.wrapping_sub(1) == v.1 {
                                        decreasing_v1 += 1;
                                    }
                                }
                            }
                            last = Some(val);
                        }
                    }
                    // We check for execs-2 because the logged execs may wrap and have something like
                    // 8 9 10 3 4 5 6 7
                    if increasing_v0 >= execs - 2
                        || increasing_v1 >= execs - 2
                        || decreasing_v0 >= execs - 2
                        || decreasing_v1 >= execs - 2
                    {
                        continue;
                    }
                }
                for j in 0..execs {
                    if let Some(val) = cmp_map.values_of(i, j) {
                        self.list.push(val);
                    }
                }
            }
        }
    }
}

impl AsSlice for CmpValuesMetadata {
    type Entry = CmpValues;
    /// Convert to a slice
    #[must_use]
    fn as_slice(&self) -> &[CmpValues] {
        self.list.as_slice()
    }
}

impl AsMutSlice for CmpValuesMetadata {
    type Entry = CmpValues;
    /// Convert to a slice
    #[must_use]
    fn as_mut_slice(&mut self) -> &mut [CmpValues] {
        self.list.as_mut_slice()
    }
}

impl CmpValuesMetadata {
    /// Creates a new [`struct@CmpValuesMetadata`]
    #[must_use]
    pub fn new() -> Self {
        Self { list: vec![] }
    }
}

/// The header for `CmpLog` hits.
#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct CmpLogHeader {
    /// how many times we met this cmp
    pub hits: u16,
    /// size?
    pub shape: u8,
    /// type of the cmplog
    pub kind: u8,
}

/// A [`CmpMap`] traces comparisons during the current execution
pub trait CmpMap: Debug {
    /// Get the number of cmps
    fn len(&self) -> usize;

    /// Get if it is empty
    #[must_use]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the number of executions for a cmp
    fn executions_for(&self, idx: usize) -> usize;

    /// Get the number of logged executions for a cmp
    fn usable_executions_for(&self, idx: usize) -> usize;

    /// Get the logged values for a cmp
    fn values_of(&self, idx: usize, execution: usize) -> Option<CmpValues>;

    /// Reset the state
    fn reset(&mut self) -> Result<(), Error>;
}

/// A [`CmpObserver`] observes the traced comparisons during the current execution using a [`CmpMap`]
pub trait CmpObserver<'a, CM, S, M>: Observer<S>
where
    CM: CmpMap,
    S: UsesInput,
    M: CmpObserverMetadata<'a, CM>,
{
    /// Get the number of usable cmps (all by default)
    fn usable_count(&self) -> usize;

    /// Get the `CmpMap`
    fn cmp_map(&self) -> &CM;

    /// Get the `CmpMap` (mutable)
    fn cmp_map_mut(&mut self) -> &mut CM;

    /// Get the observer data. By default, this is the default metadata aux data, which is `()`.
    fn cmp_observer_data(&self) -> M::Data {
        M::Data::default()
    }

    /// Add [`struct@CmpValuesMetadata`] to the State including the logged values.
    /// This routine does a basic loop filtering because loop index cmps are not interesting.
    fn add_cmpvalues_meta(&mut self, state: &mut S)
    where
        S: HasMetadata,
    {
        #[allow(clippy::option_if_let_else)] // we can't mutate state in a closure
        let meta = if let Some(meta) = state.metadata_map_mut().get_mut::<M>() {
            meta
        } else {
            state.add_metadata(M::new_metadata());
            state.metadata_map_mut().get_mut::<M>().unwrap()
        };

        let usable_count = self.usable_count();
        let cmp_observer_data = self.cmp_observer_data();

        meta.add_from(usable_count, self.cmp_map_mut(), cmp_observer_data);
    }
}
