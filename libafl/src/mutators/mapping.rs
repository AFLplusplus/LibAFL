//! Allowing mixing and matching between [`Mutator`] and [`crate::inputs::Input`] types.
use alloc::borrow::Cow;
use core::marker::PhantomData;

use libafl_bolts::{tuples::MappingFunctor, Named};

use crate::{
    inputs::MappedInput,
    mutators::{MutationResult, Mutator},
    Error,
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
///     inputs::MutVecInput,
///     mutators::{
///         ByteIncMutator, FunctionMappingMutator, MappedInputFunctionMappingMutator,
///         MutationResult, Mutator,
///     },
///     state::NopState,
/// };
///
/// type CustomInput = (Vec<u8>,);
/// fn extract_to_ref(input: &mut CustomInput) -> &mut Vec<u8> {
///     &mut input.0
/// }
///
/// fn extract_from_ref(input: &mut Vec<u8>) -> MutVecInput<'_> {
///     input.into()
/// }
///
/// // construct a mapper that works on &mut Vec<u8>
/// let inner: MappedInputFunctionMappingMutator<_, _, MutVecInput<'_>> =
///     MappedInputFunctionMappingMutator::new(extract_from_ref, ByteIncMutator::new());
/// let mut outer = FunctionMappingMutator::new(extract_to_ref, inner);
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
    name: Cow<'static, str>,
}

impl<M, F> FunctionMappingMutator<M, F> {
    /// Creates a new [`FunctionMappingMutator`]
    pub fn new(mapper: F, inner: M) -> Self
    where
        M: Named,
    {
        let name = Cow::Owned(format!("FunctionMappingMutator<{}>", inner.name()));
        Self {
            mapper,
            inner,
            name,
        }
    }
}

impl<M, S, F, IO, II> Mutator<IO, S> for FunctionMappingMutator<M, F>
where
    F: for<'a> FnMut(&'a mut IO) -> &'a mut II,
    M: Mutator<II, S>,
{
    fn mutate(&mut self, state: &mut S, input: &mut IO) -> Result<MutationResult, Error> {
        self.inner.mutate(state, (self.mapper)(input))
    }
}

impl<M, F> Named for FunctionMappingMutator<M, F> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// Mapper to use to map a [`tuple_list`] of [`Mutator`]s using [`ToFunctionMappingMutatorMapper`]s.
///
/// See the explanation of [`ToFunctionMappingMutatorMapper`] for details.
///
/// # Example
#[cfg_attr(feature = "std", doc = " ```")]
#[cfg_attr(not(feature = "std"), doc = " ```ignore")]
/// use std::vec::Vec;
///
/// use libafl::{
///     inputs::MutVecInput,
///     mutators::{
///         ByteIncMutator, MappedInputFunctionMappingMutator, MutationResult, Mutator,
///         ToFunctionMappingMutatorMapper,
///     },
///     state::NopState,
/// };
///
/// use libafl_bolts::tuples::{tuple_list, Map};
///
/// type CustomInput = (Vec<u8>,);
/// fn extract_to_ref(input: &mut CustomInput) -> &mut Vec<u8> {
///     &mut input.0
/// }
///
/// fn extract_from_ref(input: &mut Vec<u8>) -> MutVecInput<'_> {
///     input.into()
/// }
///
/// // construct a mapper that works on &mut Vec<u8>
/// let inner: MappedInputFunctionMappingMutator<_, _, MutVecInput<'_>> =
///     MappedInputFunctionMappingMutator::new(extract_from_ref, ByteIncMutator::new());
/// let inner_list = tuple_list!(inner);
/// let outer_list = inner_list.map(ToFunctionMappingMutatorMapper::new(extract_to_ref));
/// let mut outer = outer_list.0;
///
/// let mut input: CustomInput = (vec![1],);
///
/// let mut state: NopState<CustomInput> = NopState::new();
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
    M: Named,
{
    type Output = FunctionMappingMutator<M, F>;

    fn apply(&mut self, from: M) -> Self::Output {
        FunctionMappingMutator::new(self.mapper.clone(), from)
    }
}

/// Mapping [`Mutator`] using a function returning a wrapped reference (see [`MappedInput`]).
///
/// Allows using [`Mutator`]s for a certain type on (parts of) other input types that can be mapped to this type.
///
/// # Example
#[cfg_attr(feature = "std", doc = " ```")]
#[cfg_attr(not(feature = "std"), doc = " ```ignore")]
/// use std::vec::Vec;
///
/// use libafl::{
///     inputs::MutVecInput,
///     mutators::{
///         ByteIncMutator, MappedInputFunctionMappingMutator, MutationResult, Mutator,
///     },
///     state::NopState,
/// };
///
/// type CustomInput = (Vec<u8>,);
/// fn extract(input: &mut CustomInput) -> MutVecInput<'_> {
///     (&mut input.0).into()
/// }
///
/// let inner = ByteIncMutator::new();
/// let mut outer: MappedInputFunctionMappingMutator<_, _, MutVecInput<'_>> =
///     MappedInputFunctionMappingMutator::new(extract, inner);
///
/// let mut input: CustomInput = (vec![1],);
///
/// let mut state: NopState<CustomInput> = NopState::new();
/// let res = outer.mutate(&mut state, &mut input).unwrap();
/// assert_eq!(res, MutationResult::Mutated);
/// assert_eq!(input, (vec![2],));
/// ```
#[derive(Debug)]
pub struct MappedInputFunctionMappingMutator<M, F, II> {
    mapper: F,
    inner: M,
    name: Cow<'static, str>,
    phantom: PhantomData<II>,
}

impl<M, F, II> MappedInputFunctionMappingMutator<M, F, II> {
    /// Creates a new [`MappedInputFunctionMappingMutator`]
    pub fn new(mapper: F, inner: M) -> Self
    where
        M: Named,
    {
        let name = Cow::Owned(format!(
            "MappedInputFunctionMappingMutator<{}>",
            inner.name()
        ));

        Self {
            mapper,
            inner,
            name,
            phantom: PhantomData,
        }
    }
}

impl<M, S, F, IO, II> Mutator<IO, S> for MappedInputFunctionMappingMutator<M, F, II>
where
    for<'a> M: Mutator<II::Type<'a>, S>,
    for<'a> II: MappedInput + 'a,
    for<'a> F: FnMut(&'a mut IO) -> II::Type<'a>,
{
    fn mutate(&mut self, state: &mut S, input: &mut IO) -> Result<MutationResult, Error> {
        let mapped = &mut (self.mapper)(input);
        self.inner.mutate(state, mapped)
    }
}

impl<M, F, II> Named for MappedInputFunctionMappingMutator<M, F, II> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// Mapper to use to map a [`tuple_list`] of [`Mutator`]s using [`MappedInputFunctionMappingMutator`]s.
///
/// See the explanation of [`MappedInputFunctionMappingMutator`] for details.
///
/// # Example
#[cfg_attr(feature = "std", doc = " ```")]
#[cfg_attr(not(feature = "std"), doc = " ```ignore")]
/// use std::vec::Vec;
///
/// use libafl::{
///     inputs::MutVecInput,
///     mutators::{
///         ByteIncMutator, MappedInputFunctionMappingMutator, MutationResult, Mutator,
///         ToMappedInputFunctionMappingMutatorMapper,
///     },
///     state::NopState,
/// };
///
/// use libafl_bolts::tuples::{tuple_list, Map};
///
/// type CustomInput = (Vec<u8>,);
/// fn extract(input: &mut CustomInput) -> MutVecInput<'_> {
///     (&mut input.0).into()
/// }
///
/// let inner = tuple_list!(ByteIncMutator::new());
/// let outer_list: (MappedInputFunctionMappingMutator<_, _, MutVecInput<'_>>, _) =
///     inner.map(ToMappedInputFunctionMappingMutatorMapper::new(extract));
/// let mut outer = outer_list.0;
///
/// let mut input: CustomInput = (vec![1],);
///
/// let mut state: NopState<CustomInput> = NopState::new();
/// let res = outer.mutate(&mut state, &mut input).unwrap();
/// assert_eq!(res, MutationResult::Mutated);
/// assert_eq!(input, (vec![2],));
/// ```
#[derive(Debug)]
pub struct ToMappedInputFunctionMappingMutatorMapper<F, II> {
    mapper: F,
    phantom: PhantomData<II>,
}

impl<F, II> ToMappedInputFunctionMappingMutatorMapper<F, II> {
    /// Creates a new [`ToMappedInputFunctionMappingMutatorMapper`]
    pub fn new<IO>(mapper: F) -> Self
    where
        F: FnMut(IO) -> II,
    {
        Self {
            mapper,
            phantom: PhantomData,
        }
    }
}

impl<M, F, II> MappingFunctor<M> for ToMappedInputFunctionMappingMutatorMapper<F, II>
where
    F: Clone,
    M: Named,
{
    type Output = MappedInputFunctionMappingMutator<M, F, II>;

    fn apply(&mut self, from: M) -> Self::Output {
        MappedInputFunctionMappingMutator::new(self.mapper.clone(), from)
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
///     mutators::{ByteIncMutator, MutationResult, Mutator, OptionMappingMutator},
///     state::NopState,
/// };
///
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
    name: Cow<'static, str>,
}

impl<M> OptionMappingMutator<M> {
    /// Creates a new [`OptionMappingMutator`]
    pub fn new(inner: M) -> Self
    where
        M: Named,
    {
        let name = Cow::Owned(format!("OptionMappingMutator<{}>", inner.name()));
        Self { inner, name }
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
        &self.name
    }
}

/// Mapper to use to map a [`tuple_list`] of [`Mutator`]s using [`OptionMappingMutator`]s.
///
/// See the explanation of [`OptionMappingMutator`] for details.
///
/// # Example
#[cfg_attr(feature = "std", doc = " ```")]
#[cfg_attr(not(feature = "std"), doc = " ```ignore")]
/// use libafl::{
///     inputs::MutVecInput,
///     mutators::{ByteIncMutator, MutationResult, Mutator, ToOptionMappingMutatorMapper},
///     state::NopState,
/// };
/// use libafl_bolts::tuples::{tuple_list, Map};
///
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

impl<M> MappingFunctor<M> for ToOptionMappingMutatorMapper
where
    M: Named,
{
    type Output = OptionMappingMutator<M>;

    fn apply(&mut self, from: M) -> Self::Output {
        OptionMappingMutator::new(from)
    }
}
