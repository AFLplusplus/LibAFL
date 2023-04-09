use core::marker::PhantomData;

use crate::{
    inputs::convert::ConvertInput,
    mutators::{MutationResult, Mutator},
    Error,
};

#[derive(Debug)]
pub struct ConvertMutator<I, J, S, M>
where
    I: Default + ConvertInput<J>,
    J: for<'a> ConvertInput<&'a I>,
    M: Mutator<J, S>,
{
    mutator: M,
    phantom: PhantomData<(I, J, S)>,
}

impl<I, J, S, M> Mutator<I, S> for ConvertMutator<I, J, S, M>
where
    I: Default + ConvertInput<J>,
    J: for<'a> ConvertInput<&'a I>,
    M: Mutator<J, S>,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let converted = if let Ok(mut j) = J::convert_from(&input) {
            self.mutator.mutate(state, &mut j, stage_idx)?;
            I::convert_from(j).ok()
        } else {
            None
        };
        if let Some(converted) = converted {
            *input = converted;
            Ok(MutationResult::Mutated)
        } else {
            Ok(MutationResult::Skipped)
        }
    }
}
