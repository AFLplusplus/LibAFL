//! The `FavFactor` is an evaluator providing scores of corpus items.

use crate::{
    bolts::HasLen,
    corpus::Testcase,
    inputs::Input,
    Error,
};

use core::marker::PhantomData;

/// Compute the favor factor of a [`Testcase`]. Lower is better.
pub trait FavFactor<I>
    where
        I: Input,
{
    /// Computes the favor factor of a [`Testcase`]. Lower is better.
    fn compute(entry: &mut Testcase<I>) -> Result<u64, Error>;
}

/// Multiply the testcase size with the execution time.
/// This favors small and quick testcases.
#[derive(Debug, Clone)]
pub struct LenTimeMulFavFactor<I>
    where
        I: Input + HasLen,
{
    phantom: PhantomData<I>,
}

impl<I> FavFactor<I> for LenTimeMulFavFactor<I>
    where
        I: Input + HasLen,
{
    fn compute(entry: &mut Testcase<I>) -> Result<u64, Error>{
        // TODO maybe enforce entry.exec_time().is_some()
        Ok(entry.exec_time().map_or(1, |d| d.as_millis()) as u64 * entry.cached_len()? as u64)
    }
}

