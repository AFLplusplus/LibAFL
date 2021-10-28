use crate::{
    bolts::tuples::Named,
    generators::nautilus::NautilusContext,
    inputs::nautilus::NautilusInput,
    mutators::{MutationResult, Mutator},
    Error,
};

use grammartec::mutator::Mutator as BackingMutator;
use grammartec::{
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
