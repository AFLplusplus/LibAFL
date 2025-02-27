//! Allowing mixing and matching between [`Mutator`] and [`crate::inputs::Input`] types.
use alloc::borrow::Cow;

use libafl_bolts::{Named, tuples::MappingFunctor};

use crate::{
    Error,
    mutators::{MutationResult, Mutator},
};

/// Mapping [`Mutator`] using a function returning a reference.
///
/// Allows using [`Mutator`]s for a certain type on (parts of) other input types that can be mapped to this type.
///
/// # Example
#[cfg_attr(feature = "std", doc = " ```")]
#[cfg_attr(not(feature = "std"), doc = " ```ignore")]
/// use std::vec::Vec;
///
/// use libafl::{
///     mutators::{ByteIncMutator, MappingMutator, MutationResult, Mutator},
///     state::NopState,
/// };
///
/// #[derive(Debug, PartialEq)]
/// struct CustomInput(Vec<u8>);
///
/// impl CustomInput {
///     pub fn vec_mut(&mut self) -> &mut Vec<u8> {
///         &mut self.0
///     }
/// }
///
/// // construct a mutator that works on &mut Vec<u8> (since it impls `HasMutatorBytes`)
/// let inner = ByteIncMutator::new();
/// // construct a mutator that works on &mut CustomInput
/// let mut outer = MappingMutator::new(CustomInput::vec_mut, inner);
///
/// let mut input = CustomInput(vec![1]);
///
/// let mut state: NopState<CustomInput> = NopState::new();
/// let res = outer.mutate(&mut state, &mut input).unwrap();
/// assert_eq!(res, MutationResult::Mutated);
/// assert_eq!(input, CustomInput(vec![2],));
/// ```
#[derive(Debug)]
pub struct MappingMutator<M, F> {
    mapper: F,
    inner: M,
    name: Cow<'static, str>,
}

impl<M, F> MappingMutator<M, F> {
    /// Creates a new [`MappingMutator`]
    pub fn new(mapper: F, inner: M) -> Self
    where
        M: Named,
    {
        let name = Cow::Owned(format!("MappingMutator<{}>", inner.name()));
        Self {
            mapper,
            inner,
            name,
        }
    }
}

impl<M, S, F, IO, II> Mutator<IO, S> for MappingMutator<M, F>
where
    F: FnMut(&mut IO) -> &mut II,
    M: Mutator<II, S>,
{
    fn mutate(&mut self, state: &mut S, input: &mut IO) -> Result<MutationResult, Error> {
        self.inner.mutate(state, (self.mapper)(input))
    }
}

impl<M, F> Named for MappingMutator<M, F> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// Mapper to use to map a [`tuple_list`] of [`Mutator`]s using [`ToMappingMutator`]s.
///
/// See the explanation of [`MappingMutator`] for details.
///
/// # Example
#[cfg_attr(feature = "std", doc = " ```")]
#[cfg_attr(not(feature = "std"), doc = " ```ignore")]
/// use std::vec::Vec;
///
/// use libafl::{
///     mutators::{
///         ByteIncMutator, MutationResult, MutatorsTuple, ToMappingMutator,
///     },
///     state::NopState,
/// };
///  
/// use libafl_bolts::tuples::{tuple_list, Map};
///  
/// #[derive(Debug, PartialEq)]
/// struct CustomInput(Vec<u8>);
///  
/// impl CustomInput {
///     pub fn vec_mut(&mut self) -> &mut Vec<u8> {
///         &mut self.0
///     }
/// }
///  
/// // construct a mutator that works on &mut Vec<u8> (since it impls `HasMutatorBytes`)
/// let mutators = tuple_list!(ByteIncMutator::new(), ByteIncMutator::new());
/// // construct a mutator that works on &mut CustomInput
/// let mut mapped_mutators =
///     mutators.map(ToMappingMutator::new(CustomInput::vec_mut));
///  
/// let mut input = CustomInput(vec![1]);
///  
/// let mut state: NopState<CustomInput> = NopState::new();
/// let res = mapped_mutators.mutate_all(&mut state, &mut input).unwrap();
/// assert_eq!(res, MutationResult::Mutated);
/// assert_eq!(input, CustomInput(vec![3],));
/// ```
#[derive(Debug)]
pub struct ToMappingMutator<F> {
    mapper: F,
}

impl<F> ToMappingMutator<F> {
    /// Creates a new [`ToMappingMutator`]
    pub fn new(mapper: F) -> Self {
        Self { mapper }
    }
}

impl<M, F> MappingFunctor<M> for ToMappingMutator<F>
where
    F: Clone,
    M: Named,
{
    type Output = MappingMutator<M, F>;

    fn apply(&mut self, from: M) -> Self::Output {
        MappingMutator::new(self.mapper.clone(), from)
    }
}

/// Mapping [`Mutator`] for dealing with input parts wrapped in [`Option`].
///
/// Allows using [`Mutator`]s for a certain type on (parts of) other input types that can be mapped to an [`Option`] of said type.
///
/// Returns [`MutationResult::Skipped`] if the mapper returns [`None`].
///
/// # Example
#[cfg_attr(feature = "std", doc = " ```")]
#[cfg_attr(not(feature = "std"), doc = " ```ignore")]
/// use libafl::{
///     inputs::MutVecInput,
///     mutators::{ByteIncMutator, MutationResult, Mutator, OptionalMutator},
///     state::NopState,
/// };
///
/// let inner = ByteIncMutator::new();
/// let mut outer = OptionalMutator::new(inner);
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
pub struct OptionalMutator<M> {
    inner: M,
    name: Cow<'static, str>,
}

impl<M> OptionalMutator<M> {
    /// Creates a new [`OptionalMutator`]
    pub fn new(inner: M) -> Self
    where
        M: Named,
    {
        let name = Cow::Owned(format!("OptionalMutator<{}>", inner.name()));
        Self { inner, name }
    }
}

impl<I, S, M> Mutator<Option<I>, S> for OptionalMutator<M>
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

impl<M> Named for OptionalMutator<M>
where
    M: Named,
{
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// Mapper to use to map a [`tuple_list`] of [`Mutator`]s using [`OptionalMutator`]s.
///
/// See the explanation of [`OptionalMutator`] for details.
///
/// # Example
#[cfg_attr(feature = "std", doc = " ```")]
#[cfg_attr(not(feature = "std"), doc = " ```ignore")]
/// use libafl::{
///     inputs::MutVecInput,
///     mutators::{ByteIncMutator, MutationResult, Mutator, ToOptionalMutator},
///     state::NopState,
/// };
/// use libafl_bolts::tuples::{tuple_list, Map};
///
/// let inner = tuple_list!(ByteIncMutator::new());
/// let outer_list = inner.map(ToOptionalMutator);
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
pub struct ToOptionalMutator;

impl<M> MappingFunctor<M> for ToOptionalMutator
where
    M: Named,
{
    type Output = OptionalMutator<M>;

    fn apply(&mut self, from: M) -> Self::Output {
        OptionalMutator::new(from)
    }
}
