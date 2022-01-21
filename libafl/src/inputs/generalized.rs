//! The `GeneralizedInput` is an input that ca be generalized to represent a rule, used by Grimoire

use ahash::AHasher;
use alloc::{borrow::ToOwned, rc::Rc, string::String, vec::Vec};
use core::hash::Hasher;
use core::{cell::RefCell, convert::From};
use serde::{Deserialize, Serialize};

use crate::{
    bolts::{ownedref::OwnedSlice, HasLen},
    inputs::{HasBytesVec, HasTargetBytes, Input},
};

/// An item of the generalized input
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum GeneralizedItem {
    /// Real bytes
    Bytes(Vec<u8>),
    /// An insertion point
    Gap,
}

/// A bytes input with a generalized version mainly used for Grimoire
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct GeneralizedInput {
    /// The raw input bytes
    bytes: Vec<u8>,
    generalized: Option<Vec<GeneralizedItem>>,
}

impl Input for GeneralizedInput {
    /// Generate a name for this input
    fn generate_name(&self, _idx: usize) -> String {
        let mut hasher = AHasher::new_with_keys(0, 0);
        hasher.write(self.bytes());
        format!("{:016x}", hasher.finish())
    }
}

/// Rc Ref-cell from Input
impl From<GeneralizedInput> for Rc<RefCell<GeneralizedInput>> {
    fn from(input: GeneralizedInput) -> Self {
        Rc::new(RefCell::new(input))
    }
}

impl HasBytesVec for GeneralizedInput {
    #[inline]
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[inline]
    fn bytes_mut(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }
}

impl HasTargetBytes for GeneralizedInput {
    #[inline]
    fn target_bytes(&self) -> OwnedSlice<u8> {
        OwnedSlice::from(&self.bytes)
    }
}

impl HasLen for GeneralizedInput {
    #[inline]
    fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl From<Vec<u8>> for GeneralizedInput {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for GeneralizedInput {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes.to_owned())
    }
}

impl GeneralizedInput {
    /// Creates a new bytes input using the given bytes
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            generalized: None,
        }
    }

    /// Fill the generalized vector from a slice of option (None -> Gap)
    pub fn generalized_from_options(&mut self, v: &[Option<u8>]) {
        let mut res = vec![];
        let mut bytes = vec![];
        for e in v {
            match e {
                None => {
                    if bytes.len() > 0 {
                        res.push(GeneralizedItem::Bytes(bytes.clone()));
                        bytes.clear();
                    }
                    res.push(GeneralizedItem::Gap);
                }
                Some(b) => {
                    bytes.push(*b);
                }
            }
        }
        if bytes.len() > 0 {
            res.push(GeneralizedItem::Bytes(bytes));
        }
        self.generalized = Some(res);
    }

    /// Get the generalized input
    pub fn generalized(&self) -> Option<&[GeneralizedItem]> {
        self.generalized.as_ref().map(|x| x.as_slice())
    }

    /// Get the generalized input (mut)
    pub fn generalized_mut(&mut self) -> &mut Option<Vec<GeneralizedItem>> {
        &mut self.generalized
    }
}
