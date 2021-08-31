use libafl::{bolts::ownedref::OwnedSlice, inputs::{HasTargetBytes, Input}};

use lain::prelude::*;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default, Clone, NewFuzzed, Mutatable, VariableSizeObject, BinarySerialize)]
pub struct PacketData {
    typ: UnsafeEnum<PacketType, u32>,

    offset: u64,
    length: u64,

    #[lain(min = 0, max = 10)]
    data: Vec<u8>,
}

impl Fixup for PacketData {
    fn fixup<R: Rng>(&mut self, mutator: &mut Mutator<R>) {
        self.length = self.data.len() as u64;
    }
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone, FuzzerObject, ToPrimitiveU32, BinarySerialize)]
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
        OwnedSlice::Owned(serialized_data)
    }
}
