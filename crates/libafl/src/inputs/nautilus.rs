//! Input for the [`Nautilus`](https://github.com/RUB-SysSec/nautilus) grammar fuzzer methods
use alloc::{rc::Rc, string::ToString, vec::Vec};
use core::{
    cell::RefCell,
    hash::{Hash, Hasher},
};

use hashbrown::{HashMap, HashSet};
use libafl_bolts::{HasLen, ownedref::OwnedSlice};
use serde::{Deserialize, Serialize};

use crate::{
    common::nautilus::grammartec::{
        context::Context,
        newtypes::{NTermId, NodeId, RuleId},
        rule::{Rule, RuleChild, RuleIdOrCustom},
        tree::{Tree, TreeLike},
    },
    generators::nautilus::NautilusContext,
    inputs::{Input, ToTargetBytes},
};

/// An [`Input`] implementation for `Nautilus` grammar.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NautilusInput {
    /// The input representation as Tree
    pub tree: Tree,
}

impl Input for NautilusInput {}

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

    /// Create an empty [`Input`]
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

    /// Generate a `Nautilus` input from the given bytes
    pub fn unparse(&self, context: &NautilusContext, bytes: &mut Vec<u8>) {
        bytes.clear();
        self.tree.unparse(NodeId::from(0), &context.ctx, bytes);
    }

    /// Get the tree representation of this input
    #[must_use]
    pub fn tree(&self) -> &Tree {
        &self.tree
    }

    /// Get the tree representation of this input, as a mutable reference
    #[must_use]
    pub fn tree_mut(&mut self) -> &mut Tree {
        &mut self.tree
    }
}

impl Hash for NautilusInput {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.tree().paren.hash(state);
        for r in &self.tree().rules {
            match r {
                RuleIdOrCustom::Custom(a, b) => {
                    a.hash(state);
                    b.hash(state);
                }
                RuleIdOrCustom::Rule(a) => a.hash(state),
            }
        }
        self.tree().sizes.hash(state);
    }
}

/// Convert from `NautilusInput` to `BytesInput`
#[derive(Debug)]
pub struct NautilusInputConverter<'a> {
    ctx: &'a NautilusContext,
}

impl<'a> NautilusInputConverter<'a> {
    #[must_use]
    /// Create a new `NautilusInputConverter` from a context
    pub fn new(ctx: &'a NautilusContext) -> Self {
        Self { ctx }
    }
}

impl ToTargetBytes<NautilusInput> for NautilusInputConverter<'_> {
    fn to_target_bytes<'a>(&mut self, input: &'a NautilusInput) -> OwnedSlice<'a, u8> {
        let mut bytes = vec![];
        input.unparse(self.ctx, &mut bytes);
        OwnedSlice::from(bytes)
    }
}

struct NautilusParser<'a> {
    ctx: &'a Context,
    input: &'a [u8],
    memo: HashMap<(NTermId, usize), Option<(Vec<RuleIdOrCustom>, usize)>>,
    stack: HashSet<(NTermId, usize)>,
}

impl<'a> NautilusParser<'a> {
    fn new(ctx: &'a Context, input: &'a [u8]) -> Self {
        Self {
            ctx,
            input,
            memo: HashMap::new(),
            stack: HashSet::new(),
        }
    }

    fn parse_nt(&mut self, nt: NTermId, offset: usize) -> Option<(Vec<RuleIdOrCustom>, usize)> {
        if let Some(res) = self.memo.get(&(nt, offset)) {
            return res.clone();
        }
        if self.stack.contains(&(nt, offset)) {
            return None;
        }
        self.stack.insert((nt, offset));

        for rule_id in self.ctx.get_rules_for_nt(nt) {
            let rule = self.ctx.get_rule(*rule_id);
            if let Some((nodes, consumed)) = self.parse_rule(rule, *rule_id, offset) {
                self.stack.remove(&(nt, offset));
                self.memo
                    .insert((nt, offset), Some((nodes.clone(), consumed)));
                return Some((nodes, consumed));
            }
        }

        self.stack.remove(&(nt, offset));
        self.memo.insert((nt, offset), None);
        None
    }

    fn parse_rule(
        &mut self,
        rule: &Rule,
        rule_id: RuleId,
        offset: usize,
    ) -> Option<(Vec<RuleIdOrCustom>, usize)> {
        match rule {
            Rule::Plain(r) => {
                let mut current_offset = offset;
                let mut nodes = vec![RuleIdOrCustom::Rule(rule_id)];

                for child in &r.children {
                    match child {
                        RuleChild::Term(t) => {
                            if self.input.get(current_offset..current_offset + t.len())
                                == Some(t.as_slice())
                            {
                                current_offset += t.len();
                            } else {
                                return None;
                            }
                        }
                        RuleChild::NTerm(nt) => {
                            if let Some((sub_nodes, consumed)) = self.parse_nt(*nt, current_offset)
                            {
                                nodes.extend(sub_nodes);
                                current_offset += consumed;
                            } else {
                                return None;
                            }
                        }
                    }
                }
                Some((nodes, current_offset - offset))
            }
            #[cfg(feature = "regex")]
            Rule::RegExp(r) => {
                let re_str = r.hir.to_string();
                let re = regex::bytes::Regex::new(&re_str).ok()?;
                if let Some(m) = re.find_at(self.input, offset) {
                    if m.start() == offset {
                        let len = m.len();
                        let data = self.input[offset..offset + len].to_vec();
                        return Some((vec![RuleIdOrCustom::Custom(rule_id, data)], len));
                    }
                }
                None
            }
            #[cfg(not(feature = "regex"))]
            Rule::RegExp(_) => None,
            #[cfg(feature = "nautilus_py")]
            Rule::Script(_) => None,
        }
    }
}

impl crate::inputs::FromTargetBytes<NautilusInput> for NautilusInputConverter<'_> {
    fn from_target_bytes(&mut self, bytes: &[u8]) -> Result<NautilusInput, libafl_bolts::Error> {
        let start_nt = self.ctx.ctx.nt_id("START");
        let mut parser = NautilusParser::new(&self.ctx.ctx, bytes);
        if let Some((rules, consumed)) = parser.parse_nt(start_nt, 0) {
            if consumed == bytes.len() {
                return Ok(NautilusInput::new(Tree::from_rule_vec(
                    rules,
                    &self.ctx.ctx,
                )));
            }
        }
        Err(libafl_bolts::Error::illegal_argument(
            "Failed to parse bytes into NautilusInput",
        ))
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use libafl_bolts::AsSlice;

    use super::{NautilusContext, NautilusInputConverter};
    use crate::inputs::{FromTargetBytes, ToTargetBytes};

    #[test]
    #[cfg(feature = "nautilus")] // Nautilus parser requires nautilus feature (and regex)
    fn test_nautilus_parser() {
        // A simple grammar
        let rules = vec![
            vec!["START".to_string(), "{A}".to_string()],
            vec!["A".to_string(), "a{A}".to_string()],
            vec!["A".to_string(), "b".to_string()],
        ];
        let ctx = NautilusContext::new(10, &rules);
        let mut converter = NautilusInputConverter::new(&ctx);

        // Test roundtrip
        let bytes = b"aab";
        let input = converter.from_target_bytes(bytes).expect("Failed to parse");

        let out_bytes = converter.to_target_bytes(&input);
        assert_eq!(out_bytes.as_slice(), bytes.as_slice());

        // Test invalid
        let bytes = b"aac";
        assert!(converter.from_target_bytes(bytes).is_err());
    }
}
