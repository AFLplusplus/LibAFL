//! Mutators for the `Nautilus` grammmar fuzzer

use crate::{
    bolts::tuples::Named,
    corpus::Corpus,
    feedbacks::NautilusChunksMetadata,
    generators::nautilus::NautilusContext,
    inputs::nautilus::NautilusInput,
    mutators::{MutationResult, Mutator},
    state::{HasCorpus, HasMetadata},
    Error,
};

use core::{fmt::Debug, marker::PhantomData};
use grammartec::mutator::Mutator as BackingMutator;
use grammartec::{
    context::Context,
    tree::{Tree, TreeMutation},
};

/// The randomic mutator for `Nautilus` grammar.
pub struct NautilusRandomMutator<'a> {
    ctx: &'a Context,
    mutator: BackingMutator,
}

impl Debug for NautilusRandomMutator<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NautilusRandomMutator {{}}")
    }
}

impl<'a, S> Mutator<NautilusInput, S> for NautilusRandomMutator<'a> {
    fn mutate(
        &mut self,
        _state: &mut S,
        input: &mut NautilusInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        // TODO get rid of tmp
        let mut tmp = vec![];
        self.mutator
            .mut_random::<_, ()>(
                &input.tree,
                self.ctx,
                &mut |t: &TreeMutation, _ctx: &Context| {
                    tmp.extend_from_slice(t.prefix);
                    tmp.extend_from_slice(t.repl);
                    tmp.extend_from_slice(t.postfix);
                    Ok(())
                },
            )
            .unwrap();
        if tmp.is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            input.tree = Tree::from_rule_vec(tmp, self.ctx);
            Ok(MutationResult::Mutated)
        }
    }
}

impl<'a> Named for NautilusRandomMutator<'a> {
    fn name(&self) -> &str {
        "NautilusRandomMutator"
    }
}

impl<'a> NautilusRandomMutator<'a> {
    /// Creates a new [`NautilusRandomMutator`].
    #[must_use]
    pub fn new(context: &'a NautilusContext) -> Self {
        let mutator = BackingMutator::new(&context.ctx);
        Self {
            ctx: &context.ctx,
            mutator,
        }
    }
}

/// The `Nautilus` recursion mutator
// TODO calculate reucursions only for new items in corpus
pub struct NautilusRecursionMutator<'a> {
    ctx: &'a Context,
    mutator: BackingMutator,
}

impl Debug for NautilusRecursionMutator<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NautilusRecursionMutator {{}}")
    }
}

impl<'a, S> Mutator<NautilusInput, S> for NautilusRecursionMutator<'a> {
    fn mutate(
        &mut self,
        _state: &mut S,
        input: &mut NautilusInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        // TODO don't calc recursions here
        if let Some(ref mut recursions) = input.tree.calc_recursions(self.ctx) {
            // TODO get rid of tmp
            let mut tmp = vec![];
            self.mutator
                .mut_random_recursion::<_, ()>(
                    &input.tree,
                    recursions,
                    self.ctx,
                    &mut |t: &TreeMutation, _ctx: &Context| {
                        tmp.extend_from_slice(t.prefix);
                        tmp.extend_from_slice(t.repl);
                        tmp.extend_from_slice(t.postfix);
                        Ok(())
                    },
                )
                .unwrap();
            if !tmp.is_empty() {
                input.tree = Tree::from_rule_vec(tmp, self.ctx);
                return Ok(MutationResult::Mutated);
            }
        }
        Ok(MutationResult::Skipped)
    }
}

impl<'a> Named for NautilusRecursionMutator<'a> {
    fn name(&self) -> &str {
        "NautilusRecursionMutator"
    }
}

impl<'a> NautilusRecursionMutator<'a> {
    /// Creates a new [`NautilusRecursionMutator`].
    #[must_use]
    pub fn new(context: &'a NautilusContext) -> Self {
        let mutator = BackingMutator::new(&context.ctx);
        Self {
            ctx: &context.ctx,
            mutator,
        }
    }
}

/// The splicing mutator for `Nautilus` that can splice inputs together
pub struct NautilusSpliceMutator<'a, C> {
    ctx: &'a Context,
    mutator: BackingMutator,
    phantom: PhantomData<C>,
}

impl Debug for NautilusSpliceMutator<'_, ()> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NautilusSpliceMutator {{}}")
    }
}

impl<'a, S, C> Mutator<NautilusInput, S> for NautilusSpliceMutator<'a, C>
where
    C: Corpus<NautilusInput>,
    S: HasCorpus<C, NautilusInput> + HasMetadata,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut NautilusInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let meta = state
            .metadata()
            .get::<NautilusChunksMetadata>()
            .expect("NautilusChunksMetadata not in the state");
        // TODO get rid of tmp
        let mut tmp = vec![];
        self.mutator
            .mut_splice::<_, ()>(
                &input.tree,
                self.ctx,
                &meta.cks,
                &mut |t: &TreeMutation, _ctx: &Context| {
                    tmp.extend_from_slice(t.prefix);
                    tmp.extend_from_slice(t.repl);
                    tmp.extend_from_slice(t.postfix);
                    Ok(())
                },
            )
            .unwrap();
        if tmp.is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            input.tree = Tree::from_rule_vec(tmp, self.ctx);
            Ok(MutationResult::Mutated)
        }
    }
}

impl<'a, C> Named for NautilusSpliceMutator<'a, C> {
    fn name(&self) -> &str {
        "NautilusSpliceMutator"
    }
}

impl<'a, C> NautilusSpliceMutator<'a, C> {
    /// Creates a new [`NautilusSpliceMutator`].
    #[must_use]
    pub fn new(context: &'a NautilusContext) -> Self {
        let mutator = BackingMutator::new(&context.ctx);
        Self {
            ctx: &context.ctx,
            mutator,
            phantom: PhantomData,
        }
    }
}
