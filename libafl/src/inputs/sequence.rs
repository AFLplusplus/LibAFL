//! The `SequenceInput` is an input containing a sequence of other inputs

use alloc::{collections::vec_deque::VecDeque, rc::Rc, string::String, vec::Vec};
use core::{cell::RefCell, convert::From, hash::Hasher};

use ahash::AHasher;
use serde::{Deserialize, Serialize};

use crate::inputs::Input;

/// A sequence of other inputs
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, Hash)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct SequenceInput<I>
where
    I: Input,
{
    seq: VecDeque<I>,
}

impl<I> Input for SequenceInput<I>
where
    I: Input,
{
    /// Generate a name for this input
    fn generate_name(&self, idx: usize) -> String {
        let mut hasher = AHasher::new_with_keys(0, 0);
        for input in &self.seq {
            hasher.write(input.generate_name(idx).as_bytes());
        }
        format!("{:016x}", hasher.finish())
    }
}

/// Rc Ref-cell from Input
impl<I> From<SequenceInput<I>> for Rc<RefCell<SequenceInput<I>>>
where
    I: Input,
{
    fn from(input: SequenceInput<I>) -> Self {
        Rc::new(RefCell::new(input))
    }
}

impl<I> SequenceInput<I>
where
    I: Input,
{
    /// Creates a new bytes input using the given bytes
    #[must_use]
    pub fn new(vec: Vec<I>) -> Self {
        Self {
            seq: VecDeque::from(vec),
        }
    }

    /// Get a referenc to the sequence
    pub fn seq(&self) -> &VecDeque<I> {
        &self.seq
    }

    /// Get a referenc to the sequence (mut)
    pub fn seq_mut(&mut self) -> &mut VecDeque<I> {
        &mut self.seq
    }
}
