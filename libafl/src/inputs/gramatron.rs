use ahash::AHasher;
use core::hash::Hasher;

use alloc::{rc::Rc, string::String, vec::Vec};
use core::{cell::RefCell, convert::From};
use serde::{Deserialize, Serialize};

use crate::{bolts::HasLen, inputs::Input, Error};

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Terminal {
    pub state: usize,
    pub trigger_idx: usize,
    pub symbol: String,
}

impl Terminal {
    #[must_use]
    pub fn new(state: usize, trigger_idx: usize, symbol: String) -> Self {
        Self {
            state,
            trigger_idx,
            symbol,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct GramatronInput {
    /// The input representation as list of terminals
    terms: Vec<Terminal>,
}

impl Input for GramatronInput {
    /// Generate a name for this input
    #[must_use]
    fn generate_name(&self, timestamp: usize) -> String {
        let mut hasher = AHasher::new_with_keys(0, 0);
        for term in &self.terms {
            hasher.write(term.symbol.as_bytes());
        }
        format!("{}{:016x}", timestamp, hasher.finish())
    }
}

/// Rc Ref-cell from Input
impl From<GramatronInput> for Rc<RefCell<GramatronInput>> {
    fn from(input: GramatronInput) -> Self {
        Rc::new(RefCell::new(input))
    }
}

impl HasLen for GramatronInput {
    #[inline]
    fn len(&self) -> usize {
        self.terms.len()
    }
}

impl GramatronInput {
    /// Creates a new codes input using the given terminals
    #[must_use]
    pub fn new(terms: Vec<Terminal>) -> Self {
        Self { terms }
    }

    #[must_use]
    pub fn terminals(&self) -> &[Terminal] {
        &self.terms
    }

    #[must_use]
    pub fn terminals_mut(&mut self) -> &mut Vec<Terminal> {
        &mut self.terms
    }

    pub fn unparse(&self, bytes: &mut Vec<u8>) {
        bytes.clear();
        for term in &self.terms {
            bytes.extend_from_slice(term.symbol.as_bytes());
        }
    }

    pub fn crop(&self, from: usize, to: usize) -> Result<Self, Error> {
        if from < to && to <= self.terms.len() {
            let mut terms = vec![];
            terms.clone_from_slice(&self.terms[from..to]);
            Ok(Self { terms })
        } else {
            Err(Error::IllegalArgument("Invalid from or to argument".into()))
        }
    }
}
