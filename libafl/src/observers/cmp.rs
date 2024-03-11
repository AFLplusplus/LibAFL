//! The `CmpObserver` provides access to the logged values of CMP instructions

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt::Debug, marker::PhantomData};

use c2rust_bitfields::BitfieldStruct;
use hashbrown::HashMap;
use libafl_bolts::{ownedref::OwnedRefMut, serdeany::SerdeAny, AsMutSlice, AsSlice, Named};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    executors::ExitKind, inputs::UsesInput, observers::Observer, state::HasMetadata, Error,
};

/// Generic metadata trait for use in a `CmpObserver`, which adds comparisons from a `CmpObserver`
/// primarily intended for use with `AFLppCmpValuesMetadata` or `CmpValuesMetadata`
pub trait CmpObserverMetadata<'a, CM>: SerdeAny + Debug
where
    CM: CmpMap + Debug,
{
    /// Extra data used by the metadata when adding information from a `CmpObserver`, for example
    /// the `original` field in `AFLppCmpLogObserver`
    type Data: 'a + Debug + Default + Serialize + DeserializeOwned;

    /// Instantiate a new metadata instance. This is used by `CmpObserver` to create a new
    /// metadata if one is missing and `add_meta` is specified. This will typically juse call
    /// `new()`
    fn new_metadata() -> Self;

    /// Add comparisons to a metadata from a `CmpObserver`. `cmp_map` is mutable in case
    /// it is needed for a custom map, but this is not utilized for `CmpObserver` or
    /// `AFLppCmpLogObserver`.
    fn add_from(&mut self, usable_count: usize, cmp_map: &mut CM, cmp_observer_data: Self::Data);
}

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
        let meta = state.metadata_or_insert_with(|| M::new_metadata());

        let usable_count = self.usable_count();
        let cmp_observer_data = self.cmp_observer_data();

        meta.add_from(usable_count, self.cmp_map_mut(), cmp_observer_data);
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
    pub fn new(name: &'static str, map: OwnedRefMut<'a, CM>, add_meta: bool) -> Self {
        Self {
            name: name.to_string(),
            size: None,
            cmp_map: map,
            add_meta,
            data: M::Data::default(),
            phantom: PhantomData,
        }
    }

    /// Creates a new [`StdCmpObserver`] with the given name, map, and auxiliary data used to
    /// populate metadata
    #[must_use]
    pub fn with_data(
        name: &'static str,
        cmp_map: OwnedRefMut<'a, CM>,
        add_meta: bool,
        data: M::Data,
    ) -> Self {
        Self {
            name: name.to_string(),
            size: None,
            cmp_map,
            add_meta,
            data,
            phantom: PhantomData,
        }
    }

    /// Creates a new [`StdCmpObserver`] with the given name, map and reference to variable size.
    #[must_use]
    pub fn with_size(
        name: &'static str,
        cmp_map: OwnedRefMut<'a, CM>,
        add_meta: bool,
        size: OwnedRefMut<'a, usize>,
    ) -> Self {
        Self {
            name: name.to_string(),
            size: Some(size),
            cmp_map,
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
        cmp_map: OwnedRefMut<'a, CM>,
        add_meta: bool,
        data: M::Data,
        size: OwnedRefMut<'a, usize>,
    ) -> Self {
        Self {
            name: name.to_string(),
            size: Some(size),
            cmp_map,
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

/* From AFL++ cmplog.h

#define CMP_MAP_W 65536
#define CMP_MAP_H 32
#define CMP_MAP_RTN_H (CMP_MAP_H / 4)

struct cmp_header {

  unsigned hits : 24;
  unsigned id : 24;
  unsigned shape : 5;
  unsigned type : 2;
  unsigned attribute : 4;
  unsigned overflow : 1;
  unsigned reserved : 4;

} __attribute__((packed));

struct cmp_operands {

  u64 v0;
  u64 v1;
  u64 v0_128;
  u64 v1_128;

} __attribute__((packed));

struct cmpfn_operands {

  u8 v0[31];
  u8 v0_len;
  u8 v1[31];
  u8 v1_len;

} __attribute__((packed));

typedef struct cmp_operands cmp_map_list[CMP_MAP_H];

struct cmp_map {

  struct cmp_header   headers[CMP_MAP_W];
  struct cmp_operands log[CMP_MAP_W][CMP_MAP_H];

};
*/

/// A state metadata holding a list of values logged from comparisons. AFL++ RQ version.
#[derive(Debug, Default, Serialize, Deserialize)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct AFLppCmpValuesMetadata {
    /// The first map of `AFLppCmpLogVals` retrieved by running the un-mutated input
    #[serde(skip)]
    pub orig_cmpvals: HashMap<usize, Vec<CmpValues>>,
    /// The second map of `AFLppCmpLogVals` retrieved by runnning the mutated input
    #[serde(skip)]
    pub new_cmpvals: HashMap<usize, Vec<CmpValues>>,
    /// The list of logged idx and headers retrieved by runnning the mutated input
    #[serde(skip)]
    pub headers: Vec<(usize, AFLppCmpLogHeader)>,
}

libafl_bolts::impl_serdeany!(AFLppCmpValuesMetadata);

impl AFLppCmpValuesMetadata {
    /// Constructor for `AFLppCmpValuesMetadata`
    #[must_use]
    pub fn new() -> Self {
        Self {
            orig_cmpvals: HashMap::new(),
            new_cmpvals: HashMap::new(),
            headers: Vec::new(),
        }
    }

    /// Getter for `orig_cmpvals`
    #[must_use]
    pub fn orig_cmpvals(&self) -> &HashMap<usize, Vec<CmpValues>> {
        &self.orig_cmpvals
    }

    /// Getter for `new_cmpvals`
    #[must_use]
    pub fn new_cmpvals(&self) -> &HashMap<usize, Vec<CmpValues>> {
        &self.new_cmpvals
    }

    /// Getter for `headers`
    #[must_use]
    pub fn headers(&self) -> &Vec<(usize, AFLppCmpLogHeader)> {
        &self.headers
    }
}

#[derive(Debug, Copy, Clone, BitfieldStruct)]
#[repr(C, packed)]
/// Comparison header, used to describe a set of comparison values efficiently.
///
/// # Bitfields
///
/// - hits:      The number of hits of a particular comparison
/// - id:        Unused by ``LibAFL``, a unique ID for a particular comparison
/// - shape:     Whether a comparison is u8/u8, u16/u16, etc.
/// - _type:     Whether the comparison value represents an instruction (like a `cmp`) or function
///              call arguments
/// - attribute: OR-ed bitflags describing whether the comparison is <, >, =, <=, >=, or transform
/// - overflow:  Whether the comparison overflows
/// - reserved:  Reserved for future use
pub struct AFLppCmpLogHeader {
    /// The header values
    #[bitfield(name = "hits", ty = "u32", bits = "0..=23")]
    #[bitfield(name = "id", ty = "u32", bits = "24..=47")]
    #[bitfield(name = "shape", ty = "u32", bits = "48..=52")]
    #[bitfield(name = "_type", ty = "u32", bits = "53..=54")]
    #[bitfield(name = "attribute", ty = "u32", bits = "55..=58")]
    #[bitfield(name = "overflow", ty = "u32", bits = "59..=59")]
    #[bitfield(name = "reserved", ty = "u32", bits = "60..=63")]
    pub data: [u8; 8],
}
