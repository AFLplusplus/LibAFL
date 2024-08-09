//! Allowing mixing and matching between [`Mutator`] and [`crate::inputs::Input`] types.
use alloc::{borrow::Cow, vec::Vec};

use libafl_bolts::{tuples::MappingFunctor, Named};

use crate::{
    inputs::{HasMutatorBytes, Input, MutVecInput},
    mutators::{MutationResult, Mutator},
    Error,
};

/// Mapping [`Mutator`] that allows using [`Mutator`]s for a certain type on (parts of) other input types that can be mapped to this type using a function.
///
/// # Example
#[cfg_attr(feature = "std", doc = " ```")]
#[cfg_attr(not(feature = "std"), doc = " ```ignore")]
///
/// use std::vec::Vec;
///
/// use libafl::{
///     mutators::{
///         mapping::{FunctionMappingMutator, MutVecMappingMutator},
///         ByteIncMutator, MutationResult, Mutator,
///     },
///     state::NopState,
/// };
///
/// type CustomInput = (Vec<u8>,);
/// fn extract(input: &mut CustomInput) -> &mut Vec<u8> {
///     &mut input.0
/// }
///
/// let inner = MutVecMappingMutator::new(ByteIncMutator::new());
/// let mut outer = FunctionMappingMutator::new(extract, inner);
///
/// let mut input: CustomInput = (vec![1],);
///
/// let mut state: NopState<CustomInput> = NopState::new();
/// let res = outer.mutate(&mut state, &mut input).unwrap();
/// assert_eq!(res, MutationResult::Mutated);
/// assert_eq!(input, (vec![2],));
/// ```
#[derive(Debug)]
pub struct FunctionMappingMutator<M, F> {
    mapper: F,
    inner: M,
}

impl<M, F> FunctionMappingMutator<M, F> {
    /// Creates a new [`FunctionMappingMutator`]
    pub fn new(mapper: F, inner: M) -> Self {
        Self { mapper, inner }
    }
}

impl<M, S, F, IO> Mutator<IO, S> for FunctionMappingMutator<M, F>
where
    F: FnMut(&mut IO, &mut S, &mut M) -> Result<MutationResult, Error>,
{
    fn mutate(&mut self, state: &mut S, input: &mut IO) -> Result<MutationResult, Error> {
        (self.mapper)(input, state, &mut self.inner)
    }
}

impl<M, F> Named for FunctionMappingMutator<M, F> {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("FunctionMappingMutator")
    }
}

/// Mapper to use when mapping a `tuple_list` of [`Mutator`]s defined for a certain input type for (parts of) a custom input type using a [`FunctionMappingMutator`].
///
/// # Example
#[cfg_attr(feature = "std", doc = " ```")]
#[cfg_attr(not(feature = "std"), doc = " ```ignore")]
///
/// use std::vec::Vec;
///
/// use libafl_bolts::tuples::Map;
/// use tuple_list::tuple_list;
///
/// use libafl::{
///     inputs::MutVecInput,
///     mutators::{
///         mapping::{
///             ToFunctionMappingMutatorMapper, ToMutVecMappingMutatorMapper,
///         },
///         ByteIncMutator, MutationResult, Mutator,
///     },
///     state::NopState,
/// };
///
/// type CustomInput = (Vec<u8>,);
/// fn extract(input: &mut CustomInput) -> &mut Vec<u8> {
///     &mut input.0
/// }
///
/// let inner = tuple_list!(ByteIncMutator::new()).map(ToMutVecMappingMutatorMapper);
/// let outer_list = inner.map(ToFunctionMappingMutatorMapper::new(extract));
/// let mut outer = outer_list.0;
///
/// let mut input: CustomInput = (vec![1],);
///
/// let mut state: NopState<Option<MutVecInput>> = NopState::new();
/// let res = outer.mutate(&mut state, &mut input).unwrap();
/// assert_eq!(res, MutationResult::Mutated);
/// assert_eq!(input, (vec![2],));
/// ```
#[derive(Debug)]
pub struct ToFunctionMappingMutatorMapper<F> {
    mapper: F,
}

impl<F> ToFunctionMappingMutatorMapper<F> {
    /// Creates a new [`ToFunctionMappingMutatorMapper`]
    pub fn new(mapper: F) -> Self {
        Self { mapper }
    }
}

impl<M, F> MappingFunctor<M> for ToFunctionMappingMutatorMapper<F>
where
    F: Clone,
{
    type Output = FunctionMappingMutator<M, F>;

    fn apply(&mut self, from: M) -> Self::Output {
        FunctionMappingMutator::new(self.mapper.clone(), from)
    }
}

/// Mapping [`Mutator`] that allows using [`Mutator`]s for a certain type on (parts of) other input types that can be mapped to an [`Option`] of said type.
///
/// Returns [`MutationResult::Skipped`] if the mapper returns [`None`].
///
/// # Example
#[cfg_attr(feature = "std", doc = " ```")]
#[cfg_attr(not(feature = "std"), doc = " ```ignore")]
///
/// use libafl::{
///     inputs::MutVecInput,
///     mutators::{
///         ByteIncMutator, MutationResult, Mutator, OptionMappingMutator
///     },
///     state::NopState,
/// };
/// let inner = ByteIncMutator::new();
/// let mut outer = OptionMappingMutator::new(inner);
///
/// let mut input_raw = vec![1];
/// let input: MutVecInput = (&mut input_raw).into();
/// let mut input_wrapped = Some(input);
/// let mut state: NopState<Option<MutVecInput>> = NopState::new();
/// let res = outer.mutate(&mut state, &mut input_wrapped).unwrap();
/// assert_eq!(res, MutationResult::Mutated);
/// assert_eq!(input_raw, vec![2]);
///
/// let mut empty_input: Option<MutVecInput> = None;
/// let res2 = outer.mutate(&mut state, &mut empty_input).unwrap();
/// assert_eq!(res2, MutationResult::Skipped);
/// ```
#[derive(Debug)]
pub struct OptionMappingMutator<M> {
    inner: M,
}

impl<M> OptionMappingMutator<M> {
    /// Creates a new [`OptionMappingMutator`]
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

/// Mapper to use when mapping a `tuple_list` of [`Mutator`]s defined for a certain input type for (parts of) a custom input type that can be mapped to an [`Option`] of said type using a [`OptionMappingMutator`].
///
/// # Example
#[cfg_attr(feature = "std", doc = " ```")]
#[cfg_attr(not(feature = "std"), doc = " ```ignore")]
///
/// use libafl_bolts::tuples::Map;
/// use tuple_list::tuple_list;
///
/// use libafl::{
///     inputs::MutVecInput,
///     mutators::{
///         ByteIncMutator, MutationResult, Mutator, ToOptionMappingMutatorMapper
///     },
///     state::NopState,
/// };
/// let inner = tuple_list!(ByteIncMutator::new());
/// let outer_list = inner.map(ToOptionMappingMutatorMapper);
/// let mut outer = outer_list.0;
///
/// let mut input_raw = vec![1];
/// let input: MutVecInput = (&mut input_raw).into();
/// let mut input_wrapped = Some(input);
/// let mut state: NopState<Option<MutVecInput>> = NopState::new();
/// let res = outer.mutate(&mut state, &mut input_wrapped).unwrap();
/// assert_eq!(res, MutationResult::Mutated);
/// assert_eq!(input_raw, vec![2]);
///
/// let mut empty_input: Option<MutVecInput> = None;
/// let res2 = outer.mutate(&mut state, &mut empty_input).unwrap();
/// assert_eq!(res2, MutationResult::Skipped);

/// ```
#[derive(Debug)]
pub struct ToOptionMappingMutatorMapper;

impl<M> MappingFunctor<M> for ToOptionMappingMutatorMapper {
    type Output = OptionMappingMutator<M>;

    fn apply(&mut self, from: M) -> Self::Output {
        OptionMappingMutator::new(from)
    }
}
