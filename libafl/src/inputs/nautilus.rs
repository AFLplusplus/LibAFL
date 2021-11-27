use ahash::AHasher;
use core::hash::Hasher;

use alloc::{rc::Rc, string::String};
use core::{cell::RefCell, convert::From};
use serde::{Deserialize, Serialize};

use crate::{bolts::HasLen, generators::nautilus::NautilusContext, inputs::Input};

use grammartec::{
    newtypes::NodeID,
    rule::RuleIDOrCustom,
    tree::{Tree, TreeLike},
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NautilusInput {
    /// The input representation as Tree
    pub tree: Tree,
}

impl Input for NautilusInput {
    /// Generate a name for this input
    #[must_use]
    fn generate_name(&self, timestamp: usize) -> String {
        let mut hasher = AHasher::new_with_keys(0, 0);

        for term in &self.tree.rules {
            match term {
                RuleIDOrCustom::Rule(rule_id) | RuleIDOrCustom::Custom(rule_id, _) => {
                    hasher.write_usize(rule_id.to_i());
                }
            }
        }

        format!("{}{:016x}", timestamp, hasher.finish())
    }
}

/// Rc Ref-cell from Input
impl From<NautilusInput> for Rc<RefCell<NautilusInput>> {
    fn from(input: NautilusInput) -> Self {
        Rc::new(RefCell::new(input))
    }
}

impl HasLen for NautilusInput {
    #[inline]
    fn len(&self) -> usize {
        self.tree.size()
    }
}

impl NautilusInput {
    /// Creates a new codes input using the given terminals
    #[must_use]
    pub fn new(tree: Tree) -> Self {
        Self { tree }
    }

    #[must_use]
    pub fn empty() -> Self {
        Self {
            tree: Tree {
                rules: vec![],
                sizes: vec![],
                paren: vec![],
            },
        }
    }

    pub fn unparse(&self, context: &NautilusContext, bytes: &mut Vec<u8>) {
        bytes.clear();
        self.tree.unparse(NodeID::from(0), &context.ctx, bytes);
    }

    #[must_use]
    pub fn tree(&self) -> &Tree {
        &self.tree
    }

    #[must_use]
    pub fn tree_mut(&mut self) -> &mut Tree {
        &mut self.tree
    }
}
