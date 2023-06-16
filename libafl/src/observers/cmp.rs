//! The `CmpObserver` provides access to the logged values of CMP instructions

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt::Debug, marker::PhantomData};

use c2rust_bitfields::BitfieldStruct;
use hashbrown::HashMap;
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    bolts::{ownedref::OwnedRefMut, tuples::Named, AsMutSlice, AsSlice},
    executors::ExitKind,
    inputs::UsesInput,
    observers::Observer,
    state::HasMetadata,
    Error,
};

/// Compare values collected during a run
#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
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
pub struct CmpValuesMetadata {
    /// A `list` of values.
    #[serde(skip)]
    pub list: Vec<CmpValues>,
}

crate::impl_serdeany!(CmpValuesMetadata);

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
pub trait CmpObserver<CM, S>: Observer<S>
where
    CM: CmpMap,
    S: UsesInput,
{
    /// Get the number of usable cmps (all by default)
    fn usable_count(&self) -> usize;

    /// Get the `CmpMap`
    fn cmp_map(&self) -> &CM;

    /// Get the `CmpMap` (mutable)
    fn cmp_map_mut(&mut self) -> &mut CM;

    /// Add [`struct@CmpValuesMetadata`] to the State including the logged values.
    /// This routine does a basic loop filtering because loop index cmps are not interesting.
    fn add_cmpvalues_meta(&mut self, state: &mut S)
    where
        S: HasMetadata,
    {
        #[allow(clippy::option_if_let_else)] // we can't mutate state in a closure
        let meta = if let Some(meta) = state.metadata_map_mut().get_mut::<CmpValuesMetadata>() {
            meta
        } else {
            state.add_metadata(CmpValuesMetadata::new());
            state
                .metadata_map_mut()
                .get_mut::<CmpValuesMetadata>()
                .unwrap()
        };
        meta.list.clear();
        let count = self.usable_count();
        for i in 0..count {
            let execs = self.cmp_map().usable_executions_for(i);
            if execs > 0 {
                // Recongize loops and discard if needed
                if execs > 4 {
                    let mut increasing_v0 = 0;
                    let mut increasing_v1 = 0;
                    let mut decreasing_v0 = 0;
                    let mut decreasing_v1 = 0;

                    let mut last: Option<CmpValues> = None;
                    for j in 0..execs {
                        if let Some(val) = self.cmp_map().values_of(i, j) {
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
                    if let Some(val) = self.cmp_map().values_of(i, j) {
                        meta.list.push(val);
                    }
                }
            }
        }
    }
}

/// A standard [`CmpObserver`] observer
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "CM: serde::de::DeserializeOwned")]
pub struct StdCmpObserver<'a, CM, S>
where
    CM: CmpMap + Serialize,
    S: UsesInput + HasMetadata,
{
    cmp_map: OwnedRefMut<'a, CM>,
    size: Option<OwnedRefMut<'a, usize>>,
    name: String,
    add_meta: bool,
    phantom: PhantomData<S>,
}

impl<'a, CM, S> CmpObserver<CM, S> for StdCmpObserver<'a, CM, S>
where
    CM: CmpMap + Serialize + DeserializeOwned,
    S: UsesInput + Debug + HasMetadata,
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
}

impl<'a, CM, S> Observer<S> for StdCmpObserver<'a, CM, S>
where
    CM: CmpMap + Serialize + DeserializeOwned,
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

impl<'a, CM, S> Named for StdCmpObserver<'a, CM, S>
where
    CM: CmpMap + Serialize + DeserializeOwned,
    S: UsesInput + HasMetadata,
{
    fn name(&self) -> &str {
        &self.name
    }
}

impl<'a, CM, S> StdCmpObserver<'a, CM, S>
where
    CM: CmpMap + Serialize + DeserializeOwned,
    S: UsesInput + HasMetadata,
{
    /// Creates a new [`StdCmpObserver`] with the given name and map.
    #[must_use]
    pub fn new(name: &'static str, map: &'a mut CM, add_meta: bool) -> Self {
        Self {
            name: name.to_string(),
            size: None,
            cmp_map: OwnedRefMut::Ref(map),
            add_meta,
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
            phantom: PhantomData,
        }
    }
}

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
pub struct AFLppStdCmpObserver<'a, S>
where
    S: UsesInput + HasMetadata,
{
    cmp_map: OwnedRefMut<'a, AFLppCmpMap>,
    size: Option<OwnedRefMut<'a, usize>>,
    name: String,
    add_meta: bool,
    original: bool,
    phantom: PhantomData<S>,
}

impl<'a, S> CmpObserver<AFLppCmpMap, S> for AFLppStdCmpObserver<'a, S>
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

        let count = self.usable_count();
        for i in 0..count {
            if self.original {
                // Update header
                meta.headers.push((i, self.cmp_map().headers[i]));
            }

            let execs = self.cmp_map().usable_executions_for(i);
            if execs > 0 {
                // Recongize loops and discard if needed
                if execs > 4 {
                    let mut increasing_v0 = 0;
                    let mut increasing_v1 = 0;
                    let mut decreasing_v0 = 0;
                    let mut decreasing_v1 = 0;

                    let mut last: Option<CmpValues> = None;
                    for j in 0..execs {
                        if let Some(val) = self.cmp_map().values_of(i, j) {
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
                if self.original {
                    // push into orig_cmpvals
                    // println!("Adding to orig_cmpvals");
                    for j in 0..execs {
                        if let Some(val) = self.cmp_map().values_of(i, j) {
                            cmp_values.push(val);
                        }
                    }
                    // println!("idx: {cmpmap_idx} cmp_values: {:#?}", cmp_values);
                    meta.orig_cmpvals.insert(cmpmap_idx, cmp_values);
                } else {
                    // push into new_cmpvals
                    // println!("Adding to new_cmpvals");
                    for j in 0..execs {
                        if let Some(val) = self.cmp_map().values_of(i, j) {
                            cmp_values.push(val);
                        }
                    }
                    // println!("idx: {cmpmap_idx} cmp_values: {:#?}", cmp_values);
                    meta.new_cmpvals.insert(cmpmap_idx, cmp_values);
                }
            }
        }
    }
}

impl<'a, S> Observer<S> for AFLppStdCmpObserver<'a, S>
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

impl<'a, S> Named for AFLppStdCmpObserver<'a, S>
where
    S: UsesInput + HasMetadata,
{
    fn name(&self) -> &str {
        &self.name
    }
}

impl<'a, S> AFLppStdCmpObserver<'a, S>
where
    S: UsesInput + HasMetadata,
{
    /// Creates a new [`StdCmpObserver`] with the given name and map.
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

    /// Creates a new [`StdCmpObserver`] with the given name, map and reference to variable size.
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

crate::impl_serdeany!(AFLppCmpValuesMetadata);

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

/// The AFL++ `CMP_MAP_W`
pub const AFL_CMP_MAP_W: usize = 65536;
/// The AFL++ `CMP_MAP_H`
pub const AFL_CMP_MAP_H: usize = 32;
/// The AFL++ `CMP_MAP_RTN_H`
pub const AFL_CMP_MAP_RTN_H: usize = AFL_CMP_MAP_H / 4;

/// The AFL++ `CMP_TYPE_INS`
pub const AFL_CMP_TYPE_INS: u32 = 1;
/// The AFL++ `CMP_TYPE_RTN`
pub const AFL_CMP_TYPE_RTN: u32 = 2;

/// The AFL++ `cmp_header` struct
#[derive(Debug, Copy, Clone, BitfieldStruct)]
#[repr(C, packed)]
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
pub struct AFLppCmpOperands {
    v0: u64,
    v1: u64,
    v0_128: u64,
    v1_128: u64,
}

impl AFLppCmpOperands {
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
}

/// The AFL++ `cmpfn_operands` struct
#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AFLppCmpFnOperands {
    v0: [u8; 31],
    v0_len: u8,
    v1: [u8; 31],
    v1_len: u8,
}

impl AFLppCmpFnOperands {
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
}

/// A proxy union to avoid casting operands as in AFL++
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub union AFLppCmpVals {
    operands: [[AFLppCmpOperands; AFL_CMP_MAP_H]; AFL_CMP_MAP_W],
    fn_operands: [[AFLppCmpFnOperands; AFL_CMP_MAP_RTN_H]; AFL_CMP_MAP_W],
}

impl Debug for AFLppCmpVals {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AFLppCmpVals").finish_non_exhaustive()
    }
}

/// The AFL++ `cmp_map` struct, use with `StdCmpObserver`
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AFLppCmpMap {
    headers: [AFLppCmpHeader; AFL_CMP_MAP_W],
    vals: AFLppCmpVals,
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
                Some(CmpValues::Bytes((
                    self.vals.fn_operands[idx][execution].v0
                        [..(self.vals.fn_operands[idx][execution].v0_len as usize)]
                        .to_vec(),
                    self.vals.fn_operands[idx][execution].v1
                        [..(self.vals.fn_operands[idx][execution].v1_len as usize)]
                        .to_vec(),
                )))
            }
        }
    }

    fn reset(&mut self) -> Result<(), Error> {
        // For performance, we reset just the headers
        self.headers = unsafe { core::mem::zeroed() };
        // self.vals.operands = unsafe { core::mem::zeroed() };
        Ok(())
    }
}
