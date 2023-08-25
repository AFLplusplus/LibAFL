//! The `CmpObserver` provides access to the logged values of CMP instructions

use alloc::{
    alloc::alloc_zeroed,
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
use core::{alloc::Layout, fmt::Debug, marker::PhantomData};

use c2rust_bitfields::BitfieldStruct;
use hashbrown::HashMap;
use libafl_bolts::{ownedref::OwnedRefMut, serdeany::SerdeAny, AsMutSlice, AsSlice, Named};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};

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

/// A [`CmpObserver`] observer for AFL++ redqueen
#[derive(Serialize, Deserialize, Debug)]
pub struct AFLppCmpObserver<'a, S>
where
    S: UsesInput + HasMetadata,
{
    cmp_map: OwnedRefMut<'a, AFLppCmpMap>,
    size: Option<OwnedRefMut<'a, usize>>,
    name: String,
    add_meta: bool,
    original: <AFLppCmpValuesMetadata as CmpObserverMetadata<'a, AFLppCmpMap>>::Data,
    phantom: PhantomData<S>,
}

impl<'a, S> CmpObserver<'a, AFLppCmpMap, S, AFLppCmpValuesMetadata> for AFLppCmpObserver<'a, S>
where
    S: UsesInput + Debug + HasMetadata,
{
    /// Get the number of usable cmps (all by default)
    fn usable_count(&self) -> usize {
        match &self.size {
            None => self.cmp_map.as_ref().len(),
            Some(o) => *o.as_ref(),
        }
    }

    fn cmp_map(&self) -> &AFLppCmpMap {
        self.cmp_map.as_ref()
    }

    fn cmp_map_mut(&mut self) -> &mut AFLppCmpMap {
        self.cmp_map.as_mut()
    }

    fn cmp_observer_data(
        &self,
    ) -> <AFLppCmpValuesMetadata as CmpObserverMetadata<'a, AFLppCmpMap>>::Data {
        self.original
    }

    /// Add [`struct@CmpValuesMetadata`] to the State including the logged values.
    /// This routine does a basic loop filtering because loop index cmps are not interesting.
    fn add_cmpvalues_meta(&mut self, state: &mut S)
    where
        S: HasMetadata,
    {
        #[allow(clippy::option_if_let_else)] // we can't mutate state in a closure
        let meta = if let Some(meta) = state.metadata_map_mut().get_mut::<AFLppCmpValuesMetadata>()
        {
            meta
        } else {
            state.add_metadata(AFLppCmpValuesMetadata::new());
            state
                .metadata_map_mut()
                .get_mut::<AFLppCmpValuesMetadata>()
                .unwrap()
        };

        if self.original {
            // If this observer is for original input, then we have run the un-mutated input
            // Clear orig_cmpvals
            meta.orig_cmpvals.clear();
            // Clear headers
            meta.headers.clear();
        } else {
            // If this observer is for the mutated input
            meta.new_cmpvals.clear();
        }

        let usable_count = self.usable_count();
        let cmp_observer_data = self.cmp_observer_data();

        meta.add_from(usable_count, self.cmp_map_mut(), cmp_observer_data);
    }
}

impl<'a, S> Observer<S> for AFLppCmpObserver<'a, S>
where
    S: UsesInput + Debug + HasMetadata,
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

impl<'a, S> Named for AFLppCmpObserver<'a, S>
where
    S: UsesInput + HasMetadata,
{
    fn name(&self) -> &str {
        &self.name
    }
}

impl<'a, S> AFLppCmpObserver<'a, S>
where
    S: UsesInput + HasMetadata,
{
    /// Creates a new [`AFLppCmpObserver`] with the given name and map.
    #[must_use]
    pub fn new(name: &'static str, map: &'a mut AFLppCmpMap, add_meta: bool) -> Self {
        Self {
            name: name.to_string(),
            size: None,
            cmp_map: OwnedRefMut::Ref(map),
            add_meta,
            original: false,
            phantom: PhantomData,
        }
    }
    /// Setter for the flag if the executed input is a mutated one or the original one
    pub fn set_original(&mut self, v: bool) {
        self.original = v;
    }

    /// Creates a new [`AFLppCmpObserver`] with the given name, map and reference to variable size.
    #[must_use]
    pub fn with_size(
        name: &'static str,
        map: &'a mut AFLppCmpMap,
        add_meta: bool,
        original: bool,
        size: &'a mut usize,
    ) -> Self {
        Self {
            name: name.to_string(),
            size: Some(OwnedRefMut::Ref(size)),
            cmp_map: OwnedRefMut::Ref(map),
            add_meta,
            original,
            phantom: PhantomData,
        }
    }
}

/// A state metadata holding a list of values logged from comparisons. AFL++ RQ version.
#[derive(Debug, Default, Serialize, Deserialize)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct AFLppCmpValuesMetadata {
    /// The first map of AFLppCmpVals retrieved by running the un-mutated input
    #[serde(skip)]
    pub orig_cmpvals: HashMap<usize, Vec<CmpValues>>,
    /// The second map of AFLppCmpVals retrieved by runnning the mutated input
    #[serde(skip)]
    pub new_cmpvals: HashMap<usize, Vec<CmpValues>>,
    /// The list of logged idx and headers retrieved by runnning the mutated input
    #[serde(skip)]
    pub headers: Vec<(usize, AFLppCmpHeader)>,
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
    pub fn headers(&self) -> &Vec<(usize, AFLppCmpHeader)> {
        &self.headers
    }
}

impl<'a> CmpObserverMetadata<'a, AFLppCmpMap> for AFLppCmpValuesMetadata {
    type Data = bool;

    fn new_metadata() -> Self {
        Self::new()
    }

    fn add_from(
        &mut self,
        usable_count: usize,
        cmp_map: &mut AFLppCmpMap,
        cmp_observer_data: Self::Data,
    ) {
        let count = usable_count;
        for i in 0..count {
            let execs = cmp_map.usable_executions_for(i);
            if execs > 0 {
                if cmp_observer_data {
                    // Update header
                    self.headers.push((i, cmp_map.headers[i]));
                }

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

                let cmpmap_idx = i;
                let mut cmp_values = Vec::new();
                if cmp_observer_data {
                    // push into orig_cmpvals
                    // println!("Adding to orig_cmpvals");
                    for j in 0..execs {
                        if let Some(val) = cmp_map.values_of(i, j) {
                            cmp_values.push(val);
                        }
                    }
                    // println!("idx: {cmpmap_idx} cmp_values: {:#?}", cmp_values);
                    self.orig_cmpvals.insert(cmpmap_idx, cmp_values);
                } else {
                    // push into new_cmpvals
                    // println!("Adding to new_cmpvals");
                    for j in 0..execs {
                        if let Some(val) = cmp_map.values_of(i, j) {
                            cmp_values.push(val);
                        }
                    }
                    // println!("idx: {cmpmap_idx} cmp_values: {:#?}", cmp_values);
                    self.new_cmpvals.insert(cmpmap_idx, cmp_values);
                }
            }
        }
    }
}

/// The AFL++ `CMP_MAP_W`
pub const AFL_CMP_MAP_W: usize = 65536;
/// The AFL++ `CMP_MAP_H`
pub const AFL_CMP_MAP_H: usize = 32;
/// The AFL++ `CMP_MAP_RTN_H`
pub const AFL_CMP_MAP_RTN_H: usize = AFL_CMP_MAP_H / 2;

/// The AFL++ `CMP_TYPE_INS`
pub const AFL_CMP_TYPE_INS: u32 = 1;
/// The AFL++ `CMP_TYPE_RTN`
pub const AFL_CMP_TYPE_RTN: u32 = 2;

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
pub struct AFLppCmpHeader {
    #[bitfield(name = "hits", ty = "u32", bits = "0..=23")]
    #[bitfield(name = "id", ty = "u32", bits = "24..=47")]
    #[bitfield(name = "shape", ty = "u32", bits = "48..=52")]
    #[bitfield(name = "_type", ty = "u32", bits = "53..=54")]
    #[bitfield(name = "attribute", ty = "u32", bits = "55..=58")]
    #[bitfield(name = "overflow", ty = "u32", bits = "59..=59")]
    #[bitfield(name = "reserved", ty = "u32", bits = "60..=63")]
    data: [u8; 8],
}

/// The AFL++ `cmp_operands` struct
#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed)]
/// Comparison operands, represented as either two (left and right of comparison) u64 values or
/// two (left and right of comparison) u128 values, split into two u64 values. If the left and
/// right values are smaller than u64, they can be sign or zero extended to 64 bits, as the actual
/// comparison size is determined by the `hits` field of the associated `AFLppCmpHeader`.
pub struct AFLppCmpOperands {
    v0: u64,
    v1: u64,
    v0_128: u64,
    v1_128: u64,
}

impl AFLppCmpOperands {
    #[must_use]
    /// Create new `AFLppCmpOperands`
    pub fn new(v0: u64, v1: u64) -> Self {
        Self {
            v0,
            v1,
            v0_128: 0,
            v1_128: 0,
        }
    }

    #[must_use]
    /// Create new `AFLppCmpOperands` with 128-bit comparison values
    pub fn new_128bit(v0: u128, v1: u128) -> Self {
        let v0_128 = (v0 >> 64) as u64;
        let v0 = v0 as u64;
        let v1_128 = (v1 >> 64) as u64;
        let v1 = v1 as u64;

        Self {
            v0,
            v1,
            v0_128,
            v1_128,
        }
    }

    #[must_use]
    /// 64bit first cmp operand
    pub fn v0(&self) -> u64 {
        self.v0
    }

    #[must_use]
    /// 64bit second cmp operand
    pub fn v1(&self) -> u64 {
        self.v1
    }

    #[must_use]
    /// 128bit first cmp operand
    pub fn v0_128(&self) -> u64 {
        self.v0_128
    }

    #[must_use]
    /// 128bit second cmp operand
    pub fn v1_128(&self) -> u64 {
        self.v1_128
    }

    /// Set the v0 (left) side of the comparison
    pub fn set_v0(&mut self, v0: u64) {
        self.v0 = v0;
        self.v0_128 = 0;
    }

    /// Set the v1 (right) side of the comparison
    pub fn set_v1(&mut self, v1: u64) {
        self.v1 = v1;
        self.v1_128 = 0;
    }

    /// Set the v0 (left) side of the comparison from a 128-bit comparison value
    pub fn set_v0_128(&mut self, v0: u128) {
        self.v0_128 = (v0 >> 64) as u64;
        self.v0 = v0 as u64;
    }

    /// Set the v1 (right) side of the comparison from a 128-bit comparison value
    pub fn set_v1_128(&mut self, v1: u128) {
        self.v1_128 = (v1 >> 64) as u64;
        self.v1 = v1 as u64;
    }
}

/// The AFL++ `cmpfn_operands` struct
#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed)]
/// Comparison function operands, like for strcmp/memcmp, represented as two byte arrays.
pub struct AFLppCmpFnOperands {
    v0: [u8; 31],
    v0_len: u8,
    v1: [u8; 31],
    v1_len: u8,
}

impl AFLppCmpFnOperands {
    #[must_use]
    /// Create a new AFL++ function operands comparison values from two byte slices
    pub fn new(v0: &[u8], v1: &[u8]) -> Self {
        let v0_len = v0.len() as u8;
        let v1_len = v1.len() as u8;

        let mut v0_arr = [0; 31];
        let mut v1_arr = [0; 31];

        v0_arr.copy_from_slice(v0);
        v1_arr.copy_from_slice(v1);

        Self {
            v0: v0_arr,
            v0_len,
            v1: v1_arr,
            v1_len,
        }
    }

    #[must_use]
    /// first rtn operand
    pub fn v0(&self) -> &[u8; 31] {
        &self.v0
    }

    #[must_use]
    /// second rtn operand
    pub fn v0_len(&self) -> u8 {
        self.v0_len
    }

    #[must_use]
    /// first rtn operand len
    pub fn v1(&self) -> &[u8; 31] {
        &self.v1
    }

    #[must_use]
    /// second rtn operand len
    pub fn v1_len(&self) -> u8 {
        self.v1_len
    }

    /// Set the v0 (left) side of the comparison
    pub fn set_v0(&mut self, v0: &[u8]) {
        self.v0_len = v0.len() as u8;
        self.v0.copy_from_slice(v0);
    }

    /// Set the v1 (right) side of the comparison
    pub fn set_v1(&mut self, v1: &[u8]) {
        self.v1_len = v1.len() as u8;
        self.v1.copy_from_slice(v1);
    }
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
/// Comparison values
pub union AFLppCmpVals {
    operands: [[AFLppCmpOperands; AFL_CMP_MAP_H]; AFL_CMP_MAP_W],
    fn_operands: [[AFLppCmpFnOperands; AFL_CMP_MAP_RTN_H]; AFL_CMP_MAP_W],
}

impl Debug for AFLppCmpVals {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AFLppCmpVals").finish_non_exhaustive()
    }
}

impl AFLppCmpVals {
    #[must_use]
    /// Reference comparison values as comparison operands
    pub fn operands(&self) -> &[[AFLppCmpOperands; AFL_CMP_MAP_H]; AFL_CMP_MAP_W] {
        unsafe { &self.operands }
    }

    #[must_use]
    /// Mutably reference comparison values as comparison operands
    pub fn operands_mut(&mut self) -> &mut [[AFLppCmpOperands; AFL_CMP_MAP_H]; AFL_CMP_MAP_W] {
        unsafe { &mut self.operands }
    }

    #[must_use]
    /// Reference comparison values as comparison function operands
    pub fn fn_operands(&self) -> &[[AFLppCmpFnOperands; AFL_CMP_MAP_RTN_H]; AFL_CMP_MAP_W] {
        unsafe { &self.fn_operands }
    }

    #[must_use]
    /// Mutably reference comparison values as comparison function operands
    pub fn fn_operands_mut(
        &mut self,
    ) -> &mut [[AFLppCmpFnOperands; AFL_CMP_MAP_RTN_H]; AFL_CMP_MAP_W] {
        unsafe { &mut self.fn_operands }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
/// Comparison map compatible with AFL++ cmplog instrumentation
pub struct AFLppCmpMap {
    headers: [AFLppCmpHeader; AFL_CMP_MAP_W],
    vals: AFLppCmpVals,
}

impl AFLppCmpMap {
    #[must_use]
    /// Instantiate a new boxed zeroed `AFLppCmpMap`. This should be used to create a new
    /// map, because it is so large it cannot be allocated on the stack with default
    /// runtime configuration.
    pub fn boxed() -> Box<Self> {
        unsafe { Box::from_raw(alloc_zeroed(Layout::new::<AFLppCmpMap>()) as *mut AFLppCmpMap) }
    }

    #[must_use]
    /// Reference the headers for the map
    pub fn headers(&self) -> &[AFLppCmpHeader] {
        &self.headers
    }

    #[must_use]
    /// Mutably reference the headers for the map
    pub fn headers_mut(&mut self) -> &mut [AFLppCmpHeader] {
        &mut self.headers
    }

    #[must_use]
    /// Reference the values for the map
    pub fn values(&self) -> &AFLppCmpVals {
        &self.vals
    }

    #[must_use]
    /// Mutably reference the headers for the map
    pub fn values_mut(&mut self) -> &mut AFLppCmpVals {
        &mut self.vals
    }
}

impl Serialize for AFLppCmpMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let slice = unsafe {
            core::slice::from_raw_parts(
                (self as *const Self) as *const u8,
                core::mem::size_of::<Self>(),
            )
        };
        serializer.serialize_bytes(slice)
    }
}

impl<'de> Deserialize<'de> for AFLppCmpMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let map: Self = unsafe { core::ptr::read(bytes.as_ptr() as *const _) };
        Ok(map)
    }
}

impl CmpMap for AFLppCmpMap {
    fn len(&self) -> usize {
        AFL_CMP_MAP_W
    }

    fn executions_for(&self, idx: usize) -> usize {
        self.headers[idx].hits() as usize
    }

    fn usable_executions_for(&self, idx: usize) -> usize {
        if self.headers[idx]._type() == AFL_CMP_TYPE_INS {
            if self.executions_for(idx) < AFL_CMP_MAP_H {
                self.executions_for(idx)
            } else {
                AFL_CMP_MAP_H
            }
        } else if self.executions_for(idx) < AFL_CMP_MAP_RTN_H {
            self.executions_for(idx)
        } else {
            AFL_CMP_MAP_RTN_H
        }
    }

    fn values_of(&self, idx: usize, execution: usize) -> Option<CmpValues> {
        if self.headers[idx]._type() == AFL_CMP_TYPE_INS {
            unsafe {
                match self.headers[idx].shape() {
                    0 => Some(CmpValues::U8((
                        self.vals.operands[idx][execution].v0 as u8,
                        self.vals.operands[idx][execution].v1 as u8,
                    ))),
                    1 => Some(CmpValues::U16((
                        self.vals.operands[idx][execution].v0 as u16,
                        self.vals.operands[idx][execution].v1 as u16,
                    ))),
                    3 => Some(CmpValues::U32((
                        self.vals.operands[idx][execution].v0 as u32,
                        self.vals.operands[idx][execution].v1 as u32,
                    ))),
                    7 => Some(CmpValues::U64((
                        self.vals.operands[idx][execution].v0,
                        self.vals.operands[idx][execution].v1,
                    ))),
                    // TODO handle 128 bits cmps
                    // other => panic!("Invalid CmpLog shape {}", other),
                    _ => None,
                }
            }
        } else {
            unsafe {
                let v0_len = self.vals.fn_operands[idx][execution].v0_len & (0x80 - 1);
                let v1_len = self.vals.fn_operands[idx][execution].v1_len & (0x80 - 1);
                Some(CmpValues::Bytes((
                    self.vals.fn_operands[idx][execution].v0[..(v0_len as usize)].to_vec(),
                    self.vals.fn_operands[idx][execution].v1[..(v1_len as usize)].to_vec(),
                )))
            }
        }
    }

    fn reset(&mut self) -> Result<(), Error> {
        // For performance, we reset just the headers
        self.headers.fill(AFLppCmpHeader { data: [0; 8] });

        Ok(())
    }
}
