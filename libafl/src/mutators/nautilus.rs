use core::marker::PhantomData;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::tuples::Named,
    corpus::Corpus,
    generators::nautilus::NautilusContext,
    inputs::nautilus::NautilusInput,
    mutators::{MutationResult, Mutator},
    state::{HasCorpus, HasMetadata},
    Error,
};

use grammartec::mutator::Mutator as BackingMutator;
use grammartec::{
    chunkstore::ChunkStore,
    context::Context,
    tree::{Tree, TreeMutation},
};

pub struct NautilusRandomMutator<'a> {
    ctx: &'a Context,
    mutator: BackingMutator,
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
            .mut_random(
                &input.tree,
                &self.ctx,
                &mut |t: &TreeMutation, _ctx: &Context| {
                    tmp.extend_from_slice(&t.prefix);
                    tmp.extend_from_slice(&t.repl);
                    tmp.extend_from_slice(&t.postfix);
                    Ok(())
                },
            )
            .unwrap();
        if tmp.len() > 0 {
            input.tree = Tree::from_rule_vec(tmp, &self.ctx);
            Ok(MutationResult::Mutated)
        } else {
            Ok(MutationResult::Skipped)
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

// TODO calculate reucursions only for new items in corpus
pub struct NautilusRecursionMutator<'a> {
    ctx: &'a Context,
    mutator: BackingMutator,
}

impl<'a, S> Mutator<NautilusInput, S> for NautilusRecursionMutator<'a> {
    fn mutate(
        &mut self,
        _state: &mut S,
        input: &mut NautilusInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        // TODO don't calc recursions here
        if let Some(ref mut recursions) = input.tree.calc_recursions(&self.ctx) {
            // TODO get rid of tmp
            let mut tmp = vec![];
            self.mutator
                .mut_random_recursion(
                    &input.tree,
                    recursions,
                    &self.ctx,
                    &mut |t: &TreeMutation, _ctx: &Context| {
                        tmp.extend_from_slice(&t.prefix);
                        tmp.extend_from_slice(&t.repl);
                        tmp.extend_from_slice(&t.postfix);
                        Ok(())
                    },
                )
                .unwrap();
            if tmp.len() > 0 {
                input.tree = Tree::from_rule_vec(tmp, &self.ctx);
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

#[derive(Serialize, Deserialize)]
pub struct NautilusChunksMetadata {
    pub cks: ChunkStore,
}

crate::impl_serdeany!(NautilusChunksMetadata);

impl NautilusChunksMetadata {
    #[must_use]
    pub fn new(work_dir: String) -> Self {
        Self {
            cks: ChunkStore::new(work_dir),
        }
    }
}

pub struct NautilusSpliceMutator<'a, C> {
    ctx: &'a Context,
    mutator: BackingMutator,
    phantom: PhantomData<C>,
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
            .mut_splice(
                &input.tree,
                &self.ctx,
                &meta.cks,
                &mut |t: &TreeMutation, _ctx: &Context| {
                    tmp.extend_from_slice(&t.prefix);
                    tmp.extend_from_slice(&t.repl);
                    tmp.extend_from_slice(&t.postfix);
                    Ok(())
                },
            )
            .unwrap();
        if tmp.len() > 0 {
            input.tree = Tree::from_rule_vec(tmp, &self.ctx);
            Ok(MutationResult::Mutated)
        } else {
            Ok(MutationResult::Skipped)
        }
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        _stage_idx: i32,
        corpus_idx: Option<usize>,
    ) -> Result<(), Error> {
        // New entry in corpus
        if let Some(idx) = corpus_idx {
            let input = state.corpus().get(idx)?.borrow_mut().load_input()?.clone();
            let meta = state
                .metadata_mut()
                .get_mut::<NautilusChunksMetadata>()
                .expect("NautilusChunksMetadata not in the state");
            meta.cks.add_tree(input.tree, &self.ctx);
        }
        Ok(())
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
