use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::observers::concolic::{serialization_format::MessageFileReader, SymExpr, SymExprRef};

/// A metadata holding a buffer of a concolic trace.
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct ConcolicMetadata {
    /// Constraints data
    buffer: Vec<u8>,
}

impl ConcolicMetadata {
    /// Iterates over all messages in the buffer. Does not consume the buffer.
    pub fn iter_messages(&self) -> impl Iterator<Item = (SymExprRef, SymExpr)> + '_ {
        let mut parser = MessageFileReader::from_buffer(&self.buffer);
        std::iter::from_fn(move || parser.next_message()).flatten()
    }

    pub(crate) fn from_buffer(buffer: Vec<u8>) -> Self {
        Self { buffer }
    }
}

crate::impl_serdeany!(ConcolicMetadata);
