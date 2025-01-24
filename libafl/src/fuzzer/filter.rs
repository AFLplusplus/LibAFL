//! Input filter implementations
#[cfg(feature = "std")]
use core::hash::Hash;
#[cfg(feature = "std")]
use fastbloom::BloomFilter;

/// Filtering input execution in the fuzzer
pub trait InputFilter<I> {
    /// Check if the input should be executed
    fn should_execute(&mut self, input: &I) -> bool;
}

/// A pseudo-filter that will execute each input.
#[derive(Debug)]
pub struct NopInputFilter;
impl<I> InputFilter<I> for NopInputFilter {
    #[inline]
    #[must_use]
    fn should_execute(&mut self, _input: &I) -> bool {
        true
    }
}

/// A filter that probabilistically prevents duplicate execution of the same input based on a bloom filter.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct BloomInputFilter {
    bloom: BloomFilter,
}

#[cfg(feature = "std")]
impl BloomInputFilter {
    #[must_use]
    /// Create a new [`BloomInputFilter`]
    pub fn new(items_count: usize, fp_p: f64) -> Self {
        let bloom = BloomFilter::with_false_pos(fp_p).expected_items(items_count);
        Self { bloom }
    }
}

#[cfg(feature = "std")]
impl<I: Hash> InputFilter<I> for BloomInputFilter {
    #[inline]
    #[must_use]
    fn should_execute(&mut self, input: &I) -> bool {
        !self.bloom.insert(input)
    }
}
