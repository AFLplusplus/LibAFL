//! The `FavFactor` is an evaluator providing scores of corpus items.

use crate::{bolts::HasLen, corpus::Testcase, inputs::Input, Error, state::HasMetadata};

use core::marker::PhantomData;

/// Compute the favor factor of a [`Testcase`]. Lower is better.
pub trait FavFactor<I, S>
where
    I: Input,
    S: HasMetadata,
{
    /// Computes the favor factor of a [`Testcase`]. Lower is better.
    fn compute(entry: &mut Testcase<I>, state: &S) -> Result<f64, Error>;
}

/// Multiply the testcase size with the execution time.
/// This favors small and quick testcases.
#[derive(Debug, Clone)]
pub struct LenTimeMulFavFactor<I, S>
where
    I: Input + HasLen,
    S: HasMetadata
{
    phantom: PhantomData<(I, S)>,
}

impl<I, S> FavFactor<I, S> for LenTimeMulFavFactor<I, S>
where
    I: Input + HasLen,
    S: HasMetadata
{
    fn compute(entry: &mut Testcase<I>, _state: &S) -> Result<f64, Error> {
        // TODO maybe enforce entry.exec_time().is_some()
        Ok(entry.exec_time().map_or(1, |d| d.as_millis()) as f64 * entry.cached_len()? as f64)
    }
}