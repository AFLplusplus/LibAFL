//! Allowing mixing and matching between [`Mutator`] and [`crate::inputs::Input`] types.
use std::borrow::Cow;

use crate::{
    mutators::{MutationResult, Mutator},
    Error,
};

use libafl_bolts::Named;

/// Mutator that allows using [`Mutator`]s that expect different [`crate::inputs::Input`] types.
///
/// Only use when necessary, as it introduces a function call on each mutation.
///
/// ```rust
/// use libafl::{
///     inputs::{BytesInput, HasMutatorBytes},
///     mutators::{MappingMutator, Mutator, MutationResult},
///     prelude::{ByteIncMutator, NopState},
/// };
///
/// struct CustomInput(pub BytesInput); // dummy custom input that shows how to apply mutators for any BytesInput
///
/// let mut mutator = MappingMutator::new(
///     |custom_input: &mut CustomInput| -> &mut BytesInput { &mut custom_input.0 },
///     ByteIncMutator::new(), // example for a mutator of a different type
/// );
///
/// let mut state: NopState<CustomInput> = NopState::new();
///
/// let input_content = 1;
/// let mut input = CustomInput(BytesInput::new(vec![input_content]));
///
/// let res = mutator.mutate(&mut state, &mut input);
///
/// assert_eq!(res.unwrap(), MutationResult::Mutated);
/// assert_eq!(input.0.bytes(), vec![input_content + 1]);
/// ```
#[derive(Debug)]
pub struct MappingMutator<M, OI, II> {
    mapper: for<'a> fn(&'a mut OI) -> &'a mut II,
    inner: M,
}

impl<M, OI, II> MappingMutator<M, OI, II> {
    /// Creates a new [`MappingMutator`] based on another [`Mutator`] and a function that maps the outer [`crate::inputs::Input`] to what the inner [`Mutator`] expects.
    pub fn new(mapper: for<'a> fn(&'a mut OI) -> &'a mut II, inner: M) -> Self {
        Self { mapper, inner }
    }
}

impl<S, M, OI, II> Mutator<OI, S> for MappingMutator<M, OI, II>
where
    M: Mutator<II, S>,
{
    fn mutate(&mut self, state: &mut S, input: &mut OI) -> Result<MutationResult, Error> {
        self.inner.mutate(state, (self.mapper)(input))
    }
}

impl<M, OI, II> Named for MappingMutator<M, OI, II> {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("MappingMutator")
    }
}
