use libafl::{
    bolts::{ownedref::OwnedSlice, HasLen},
    inputs::{HasTargetBytes, Input},
};

use lain::prelude::*;

use serde::{Deserialize, Serialize};
use std::hash::Hash;

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Default,
    Clone,
    NewFuzzed,
    Mutatable,
    VariableSizeObject,
    BinarySerialize,
)]
pub struct PacketData {
    pub typ: UnsafeEnum<PacketType, u32>,

    pub offset: u64,
    pub length: u64,

    #[lain(max = 10)]
    pub data: Vec<u8>,
}

impl Fixup for PacketData {
    fn fixup<R: Rng>(&mut self, _mutator: &mut Mutator<R>) {
        self.length = self.data.len() as u64;
    }
}

#[derive(
    Serialize, Deserialize, Debug, Copy, Clone, FuzzerObject, ToPrimitiveU32, BinarySerialize, Hash,
)]
#[repr(u32)]
pub enum PacketType {
    Read = 0x0,
    Write = 0x1,
    Reset = 0x2,
}

impl Default for PacketType {
    fn default() -> Self {
        PacketType::Read
    }
}

impl Input for PacketData {
    fn generate_name(&self, idx: usize) -> String {
        format!("id_{}", idx)
    }
}

impl HasTargetBytes for PacketData {
    #[inline]
    fn target_bytes(&self) -> OwnedSlice<u8> {
        let mut serialized_data = Vec::with_capacity(self.serialized_size());
        self.binary_serialize::<_, LittleEndian>(&mut serialized_data);
        OwnedSlice::from(serialized_data)
    }
}

impl HasLen for PacketData {
    fn len(&self) -> usize {
        self.serialized_size()
    }
}

impl Hash for PacketData {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self.typ {
            UnsafeEnum::Invalid(a) => a.hash(state),
            UnsafeEnum::Valid(a) => a.hash(state),
        }
        self.offset.hash(state);
        self.length.hash(state);
        self.data.hash(state);
    }
}
