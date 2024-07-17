//! Allowing mixing and matching between [`Mutator`] and [`crate::inputs::Input`] types.
use std::borrow::Cow;

use crate::{
    inputs::MutVecInput,
    mutators::{MutationResult, Mutator},
    Error,
};

use alloc::vec::Vec;
use libafl_bolts::{tuples::MappingFunctor, Named};

#[derive(Debug)]
pub struct MutVecMappingMutator<M> {
    inner: M,
}

impl<M> MutVecMappingMutator<M> {
    pub fn new(inner: M) -> Self {
        Self { inner }
    }
}

impl<S, M> Mutator<Vec<u8>, S> for MutVecMappingMutator<M>
where
    M: for<'a> Mutator<MutVecInput<'a>, S>,
{
    fn mutate(&mut self, state: &mut S, input: &mut Vec<u8>) -> Result<MutationResult, Error> {
        self.inner.mutate(state, &mut input.into())
    }
}

impl<M> Named for MutVecMappingMutator<M>
where
    M: Named,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("MutVecMappingMutator")
    }
}

#[derive(Debug)]
pub struct ToMutVecMappingMutatorMapper;

impl<M> MappingFunctor<M> for ToMutVecMappingMutatorMapper {
    type Output = MutVecMappingMutator<M>;

    fn apply(&mut self, from: M) -> Self::Output {
        MutVecMappingMutator::new(from)
    }
}

#[derive(Debug)]
pub struct FunctionMappingMutator<M, IO, II> {
    mapper: fn(&mut IO) -> &mut II,
    inner: M,
}

impl<M, IO, II> FunctionMappingMutator<M, IO, II> {
    fn new(mapper: fn(&mut IO) -> &mut II, inner: M) -> Self {
        Self { mapper, inner }
    }
}

impl<M, S, IO, II> Mutator<IO, S> for FunctionMappingMutator<M, IO, II>
where
    M: Mutator<II, S>,
{
    fn mutate(&mut self, state: &mut S, input: &mut IO) -> Result<MutationResult, Error> {
        self.inner.mutate(state, (self.mapper)(input))
    }
}

impl<M, IO, II> Named for FunctionMappingMutator<M, IO, II>
where
    M: Named,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("FunctionMappingMutator")
    }
}

#[derive(Debug)]
pub struct ToFunctionMappingMutatorMapper<IO, II> {
    mapper: for<'a> fn(&'a mut IO) -> &'a mut II,
}

impl<IO, II> ToFunctionMappingMutatorMapper<IO, II> {
    pub fn new(mapper: for<'a> fn(&'a mut IO) -> &'a mut II) -> Self {
        Self { mapper }
    }
}

impl<M, IO, II> MappingFunctor<M> for ToFunctionMappingMutatorMapper<IO, II> {
    type Output = FunctionMappingMutator<M, IO, II>;

    fn apply(&mut self, from: M) -> Self::Output {
        FunctionMappingMutator::new(self.mapper, from)
    }
}

#[derive(Debug)]
pub struct OptionMappingMutator<M> {
    inner: M,
}

impl<M> OptionMappingMutator<M> {
    pub fn new(inner: M) -> Self {
        Self { inner }
    }
}

impl<I, S, M> Mutator<Option<I>, S> for OptionMappingMutator<M>
where
    M: Mutator<I, S>,
{
    fn mutate(&mut self, state: &mut S, input: &mut Option<I>) -> Result<MutationResult, Error> {
        match input {
            None => Ok(MutationResult::Skipped),
            Some(i) => self.inner.mutate(state, i),
        }
    }
}

impl<M> Named for OptionMappingMutator<M>
where
    M: Named,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("OptionMappingMutator")
    }
}

#[derive(Debug)]
pub struct ToOptionMappingMutatorMapper;

impl<M> MappingFunctor<M> for ToOptionMappingMutatorMapper {
    type Output = OptionMappingMutator<M>;

    fn apply(&mut self, from: M) -> Self::Output {
        OptionMappingMutator::new(from)
    }
}

#[cfg(test)]
mod test {

    use libafl_bolts::tuples::Map;
    use tuple_list::tuple_list;

    use crate::{
        inputs::MutVecInput,
        prelude::{ByteIncMutator, MutationResult, Mutator, NopState},
    };

    use super::{OptionMappingMutator, ToOptionMappingMutatorMapper};

    #[test]
    fn test_option_mapping_mutator() {
        let inner = ByteIncMutator::new();
        let mut outer = OptionMappingMutator::new(inner);

        let mut input_raw = vec![1];
        let input: MutVecInput = (&mut input_raw).into();
        let mut input_wrapped = Some(input);
        let mut state: NopState<Option<MutVecInput>> = NopState::new();
        let res = outer.mutate(&mut state, &mut input_wrapped).unwrap();
        assert_eq!(res, MutationResult::Mutated);
        assert_eq!(input_raw, vec![2]);

        let mut empty_input: Option<MutVecInput> = None;
        let res2 = outer.mutate(&mut state, &mut empty_input).unwrap();
        assert_eq!(res2, MutationResult::Skipped);
    }

    #[test]
    fn test_option_mapping_mutator_tuple_mapper() {
        let inner = tuple_list!(ByteIncMutator::new());
        let outer_list = inner.map(ToOptionMappingMutatorMapper);
        let mut outer = outer_list.0;

        let mut input_raw = vec![1];
        let input: MutVecInput = (&mut input_raw).into();
        let mut input_wrapped = Some(input);
        let mut state: NopState<Option<MutVecInput>> = NopState::new();
        let res = outer.mutate(&mut state, &mut input_wrapped).unwrap();
        assert_eq!(res, MutationResult::Mutated);
        assert_eq!(input_raw, vec![2]);

        let mut empty_input: Option<MutVecInput> = None;
        let res2 = outer.mutate(&mut state, &mut empty_input).unwrap();
        assert_eq!(res2, MutationResult::Skipped);
    }
}
