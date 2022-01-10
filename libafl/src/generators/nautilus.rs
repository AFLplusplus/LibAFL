//! Generators for the [`Nautilus`](https://github.com/RUB-SysSec/nautilus) grammar fuzzer
use crate::{generators::Generator, inputs::nautilus::NautilusInput, Error};
use alloc::{string::String, vec::Vec};
use core::fmt::Debug;
use grammartec::context::Context;
use std::{fs, io::BufReader, path::Path};

pub use grammartec::newtypes::NTermID;

/// The nautilus context for a generator
pub struct NautilusContext {
    /// The nautilus context for a generator
    pub ctx: Context,
}

impl Debug for NautilusContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NautilusContext {{}}",)
    }
}

impl NautilusContext {
    /// Returns a new [`NautilusGenerator`]
    #[must_use]
    pub fn new(tree_depth: usize, rules: &[Vec<String>]) -> Self {
        assert!(!rules.is_empty());
        assert!(!rules[0].is_empty());
        let mut ctx = Context::new();
        for rule in rules {
            ctx.add_rule(&rule[0], rule[1].as_bytes());
        }
        let root = "{".to_string() + &rules[0][0] + "}";
        ctx.add_rule("START", root.as_bytes());
        ctx.initialize(tree_depth);
        Self { ctx }
    }

    /// Create a new [`NautilusContext`] from a file
    #[must_use]
    pub fn from_file<P: AsRef<Path>>(tree_depth: usize, grammar_file: P) -> Self {
        let file = fs::File::open(grammar_file).expect("Cannot open grammar file");
        let reader = BufReader::new(file);
        let rules: Vec<Vec<String>> =
            serde_json::from_reader(reader).expect("Cannot parse grammar file");
        Self::new(tree_depth, &rules)
    }
}

#[derive(Clone)]
/// Generates random inputs from a grammar
pub struct NautilusGenerator<'a> {
    /// The nautilus context of the grammar
    pub ctx: &'a Context,
}

impl Debug for NautilusGenerator<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NautilusGenerator {{}}",)
    }
}

impl<'a, S> Generator<NautilusInput, S> for NautilusGenerator<'a> {
    fn generate(&mut self, _state: &mut S) -> Result<NautilusInput, Error> {
        let nonterm = self.nonterminal("START");
        let len = self.ctx.get_random_len_for_nt(&nonterm);
        let mut input = NautilusInput::empty();
        self.generate_from_nonterminal(&mut input, nonterm, len);
        Ok(input)
    }

    fn generate_dummy(&self, _state: &mut S) -> NautilusInput {
        NautilusInput::empty()
    }
}

impl<'a> NautilusGenerator<'a> {
    /// Returns a new [`NautilusGenerator`]
    #[must_use]
    pub fn new(context: &'a NautilusContext) -> Self {
        Self { ctx: &context.ctx }
    }

    /// Gets the nonterminal from this input
    // TODO create from a python grammar
    #[must_use]
    pub fn nonterminal(&self, name: &str) -> NTermID {
        self.ctx.nt_id(name)
    }

    /// Generates a [`NautilusInput`] from a nonterminal
    pub fn generate_from_nonterminal(&self, input: &mut NautilusInput, start: NTermID, len: usize) {
        input.tree_mut().generate_from_nt(start, len, self.ctx);
    }
}
