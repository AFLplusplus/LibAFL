//! A wrapper input that can be used to mutate parts of a byte slice
//! The `BytesInput` is the "normal" input, a map of bytes, that can be sent directly to the client
//! (As opposed to other, more abstract, inputs, like an Grammar-Based AST Input)

use alloc::vec::Vec;
use core::{
    cmp::{min, Ordering},
    ops::{Bound, Range, RangeBounds},
};

use libafl_bolts::HasLen;

use super::HasMutatorBytes;

fn start_index<R>(range: &R) -> usize
where
    R: RangeBounds<usize>,
{
    match range.start_bound() {
        Bound::Unbounded => 0,
        Bound::Included(start) => *start,
        Bound::Excluded(start) => start + 1,
    }
}

fn end_index<R>(range: &R, parent_len: usize) -> usize
where
    R: RangeBounds<usize>,
{
    match range.end_bound() {
        Bound::Unbounded => parent_len,
        Bound::Included(end) => end + 1,
        Bound::Excluded(end) => *end,
    }
}

/// A [`BytesSubInput`] makes it possible to use [`Mutator`]`s` that work on
/// inputs implementing the [`HasMutatorBytes`] for a sub-range of this input.
/// For example, we can do the following:
/// ```rust
/// # extern crate alloc;
/// # extern crate libafl;
/// # use libafl::inputs::{BytesInput, HasMutatorBytes};
/// # use alloc::vec::Vec;
///
/// let mut bytes_input = BytesInput::new(vec![1,2,3]);
/// let mut bsi = bytes_input.sub_input(1..);
///
/// // Run any mutations on the sub input
/// bsi.bytes_mut()[0] = 42;
///
/// // The mutations are applied to the underlying input
/// assert_eq!(bytes_input.bytes()[1], 42);
/// ```
#[derive(Debug)]
pub struct BytesSubInput<'a, I>
where
    I: HasMutatorBytes + ?Sized,
{
    /// The (complete) parent input we will work on
    pub(crate) parent_input: &'a mut I,
    /// The range inside the parent input we will work on
    pub(crate) range: Range<usize>,
}

impl<'a, I> BytesSubInput<'a, I>
where
    I: HasMutatorBytes + ?Sized + HasLen,
{
    /// Creates a new `BytesSubInput` that's a view on an input with mutator bytes.
    /// The sub input can then be used to mutate parts of the original input.
    pub fn new<R>(parent_input: &'a mut I, range: R) -> Self
    where
        R: RangeBounds<usize>,
    {
        let parent_len = parent_input.len();

        BytesSubInput {
            parent_input,
            range: Range {
                start: start_index(&range),
                end: end_index(&range, parent_len),
            },
        }
    }

    /// The inclusive start index in the parent buffer
    fn start_index(&self) -> usize {
        self.range.start
    }

    /// The exclusive end index in the parent buffer
    fn end_index(&self) -> usize {
        self.range.end
    }

    /// Creates a sub range in the current own range
    fn sub_range<R2>(&self, range: R2) -> (Bound<usize>, Bound<usize>)
    where
        R2: RangeBounds<usize>,
    {
        let start = match (self.range.start_bound(), range.start_bound()) {
            (Bound::Unbounded, Bound::Unbounded) => Bound::Unbounded,
            (Bound::Excluded(bound), Bound::Unbounded)
            | (Bound::Unbounded, Bound::Excluded(bound)) => Bound::Excluded(*bound),
            (Bound::Included(bound), Bound::Unbounded)
            | (Bound::Unbounded, Bound::Included(bound)) => Bound::Included(*bound),
            (Bound::Included(own), Bound::Included(other)) => Bound::Included(own + other),
            (Bound::Included(own), Bound::Excluded(other))
            | (Bound::Excluded(own), Bound::Included(other)) => Bound::Excluded(own + other),
            (Bound::Excluded(own), Bound::Excluded(other)) => Bound::Excluded(own + other + 1),
        };

        let end = match (self.range.end_bound(), range.end_bound()) {
            (Bound::Unbounded, Bound::Unbounded) => Bound::Unbounded,
            (Bound::Excluded(bound), Bound::Unbounded) => Bound::Excluded(*bound),
            (Bound::Unbounded, Bound::Excluded(bound)) => {
                Bound::Excluded(self.end_index() - *bound)
            }
            (Bound::Included(bound), Bound::Unbounded) => Bound::Included(*bound),
            (Bound::Unbounded, Bound::Included(bound)) => {
                Bound::Included(self.end_index() - *bound)
            }
            (Bound::Included(own), Bound::Included(other)) => {
                Bound::Included(min(*own, self.start_index() + other))
            }
            (Bound::Included(own), Bound::Excluded(other)) => {
                Bound::Included(min(*own, self.start_index() + other - 1))
            }
            (Bound::Excluded(own), Bound::Included(other)) => {
                Bound::Included(min(*own - 1, self.start_index() + other))
            }
            (Bound::Excluded(own), Bound::Excluded(other)) => {
                Bound::Excluded(min(*own, self.start_index() + other))
            }
        };

        (start, end)
    }
}

impl<'a, I> HasMutatorBytes for BytesSubInput<'a, I>
where
    I: HasMutatorBytes + HasLen,
{
    #[inline]
    fn bytes(&self) -> &[u8] {
        &self.parent_input.bytes()[self.range.clone()]
    }

    #[inline]
    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.parent_input.bytes_mut()[self.range.clone()]
    }

    fn resize(&mut self, new_len: usize, value: u8) {
        let start_index = self.start_index();
        let end_index = self.end_index();
        let old_len = end_index - start_index;

        match new_len.cmp(&old_len) {
            Ordering::Equal => {
                // Nothing to do here.
            }
            Ordering::Greater => {
                // We grow. Resize the underlying buffer, then move the entries past our `end_index` back.
                let diff = new_len - old_len;

                let old_parent_len = self.parent_input.len();
                self.parent_input.resize(old_parent_len + diff, value);

                if old_parent_len > end_index {
                    // the parent has a reminder, move it back.
                    let parent_bytes = self.parent_input.bytes_mut();

                    // move right
                    let (_, rest) = parent_bytes.split_at_mut(start_index + old_len);
                    rest.copy_within(0..rest.len() - diff, diff);
                    let (new, _rest) = rest.split_at_mut(diff);

                    // fill
                    new.fill(value);
                }

                self.range.end += diff;
            }
            Ordering::Less => {
                // We shrink. Remove the values, then remove the underlying buffer.
                let diff = old_len - new_len;

                let parent_bytes = self.parent_input.bytes_mut();

                // move left
                let (_, rest) = parent_bytes.split_at_mut(start_index + new_len);
                rest.copy_within(diff.., 0);

                // cut off the rest
                self.parent_input
                    .resize(self.parent_input.len() - diff, value);

                self.range.end -= diff;
            }
        }
    }

    fn extend<'b, IT: IntoIterator<Item = &'b u8>>(&mut self, iter: IT) {
        let old_len = self.end_index() - self.start_index();

        let new_values: Vec<u8> = iter.into_iter().copied().collect();
        self.resize(old_len + new_values.len(), 0);
        self.bytes_mut()[old_len..].copy_from_slice(&new_values);
    }

    /// Creates a splicing iterator that replaces the specified range in the vector
    /// with the given `replace_with` iterator and yields the removed items.
    /// `replace_with` does not need to be the same length as range.
    /// Refer to the docs of [`Vec::splice`]
    fn splice<R2, IT>(
        &mut self,
        range: R2,
        replace_with: IT,
    ) -> alloc::vec::Splice<'_, IT::IntoIter>
    where
        R2: RangeBounds<usize>,
        IT: IntoIterator<Item = u8>,
    {
        let range = self.sub_range(range);
        self.parent_input.splice(range, replace_with)
    }

    fn drain<R2>(&mut self, range: R2) -> alloc::vec::Drain<'_, u8>
    where
        R2: RangeBounds<usize>,
    {
        let drain = self.parent_input.drain(self.sub_range(range));
        self.range.end -= drain.len();
        drain
    }
}

impl<'a, I> HasLen for BytesSubInput<'a, I>
where
    I: HasMutatorBytes + HasLen,
{
    #[inline]
    fn len(&self) -> usize {
        self.range.end - self.range.start
    }
}

#[cfg(test)]
mod tests {

    use alloc::vec::Vec;

    use libafl_bolts::HasLen;

    use crate::{
        inputs::{BytesInput, HasMutatorBytes},
        mutators::{havoc_mutations_no_crossover, MutatorsTuple},
        state::NopState,
    };

    fn init_bytes_input() -> (BytesInput, usize) {
        let bytes_input = BytesInput::new(vec![1, 2, 3, 4, 5, 6, 7]);
        let len_orig = bytes_input.len();
        (bytes_input, len_orig)
    }

    #[test]
    fn test_bytessubinput() {
        let (mut bytes_input, len_orig) = init_bytes_input();

        let mut bsi = bytes_input.sub_input(0..1);
        assert_eq!(bsi.len(), 1);
        bsi.bytes_mut()[0] = 2;
        assert_eq!(bytes_input.bytes()[0], 2);

        let mut bsi = bytes_input.sub_input(1..=2);
        assert_eq!(bsi.len(), 2);
        bsi.bytes_mut()[0] = 3;
        assert_eq!(bytes_input.bytes()[1], 3);

        let mut bsi = bytes_input.sub_input(..);
        assert_eq!(bsi.len(), len_orig);
        bsi.bytes_mut()[0] = 1;
        bsi.bytes_mut()[1] = 2;
        assert_eq!(bytes_input.bytes()[0], 1);
    }

    #[test]
    fn test_bytessubinput_resize() {
        let (mut bytes_input, len_orig) = init_bytes_input();
        let bytes_input_orig = bytes_input.clone();

        let mut bsi = bytes_input.sub_input(2..);
        assert_eq!(bsi.len(), len_orig - 2);
        bsi.resize(len_orig, 0);
        assert_eq!(bsi.bytes()[bsi.len() - 1], 0);
        assert_eq!(bsi.len(), len_orig);
        assert_eq!(bytes_input.len(), len_orig + 2);
        assert_eq!(bytes_input.bytes()[bytes_input.len() - 1], 0);

        let (mut bytes_input, len_orig) = init_bytes_input();

        let mut bsi = bytes_input.sub_input(..2);
        assert_eq!(bsi.len(), 2);
        bsi.resize(3, 0);
        assert_eq!(bsi.len(), 3);
        assert_eq!(bsi.bytes()[bsi.len() - 1], 0);
        assert_eq!(bytes_input.len(), len_orig + 1);

        let mut bsi = bytes_input.sub_input(..3);
        assert_eq!(bsi.len(), 3);
        bsi.resize(2, 0);
        assert_eq!(bsi.len(), 2);
        assert_eq!(bytes_input, bytes_input_orig);

        let mut bsi = bytes_input.sub_input(2..=2);
        bsi.resize(2, 0);
        bsi.resize(1, 0);
        assert_eq!(bytes_input, bytes_input_orig);

        let mut bsi = bytes_input.sub_input(..);
        assert_eq!(bsi.len(), bytes_input_orig.len());
        bsi.resize(1, 0);
        assert_eq!(bsi.len(), 1);
        bsi.resize(10, 0);
        assert_eq!(bsi.len(), 10);
        assert_eq!(bytes_input.len(), 10);
        assert_eq!(bytes_input.bytes()[2], 0);

        let mut bsi = bytes_input.sub_input(..);
        bsi.resize(1, 0);
        assert_eq!(bytes_input.len(), 1);
    }

    #[test]
    fn test_bytessubinput_drain_extend() {
        let (mut bytes_input, len_orig) = init_bytes_input();
        let bytes_input_cloned = bytes_input.clone();

        let mut bsi = bytes_input.sub_input(..2);
        let drained: Vec<_> = bsi.drain(..).collect();
        assert_eq!(bsi.len(), 0);
        assert_eq!(bytes_input.len(), len_orig - 2);

        let mut bsi = bytes_input.sub_input(..0);
        assert_eq!(bsi.len(), 0);
        let drained_len = drained.len();
        bsi.extend(&drained[..]);
        assert_eq!(bsi.len(), drained_len);
        assert_eq!(bytes_input, bytes_input_cloned);
    }

    #[test]
    fn test_bytessubinput_mutator() {
        let (mut bytes_input, _len_orig) = init_bytes_input();
        let bytes_input_cloned = bytes_input.clone();

        let mut bsi = bytes_input.sub_input(..2);

        let mut state: NopState<BytesInput> = NopState::new();

        let result = havoc_mutations_no_crossover().mutate_all(&mut state, &mut bsi);
        assert!(result.is_ok());
        assert_ne!(bytes_input, bytes_input_cloned);
    }

    #[test]
    fn test_ranges() {
        let mut bytes_input = BytesInput::new(vec![1, 2, 3]);

        assert_eq!(bytes_input.sub_input(..1).start_index(), 0);
        assert_eq!(bytes_input.sub_input(1..=1).start_index(), 1);
        assert_eq!(bytes_input.sub_input(..1).end_index(), 1);
        assert_eq!(bytes_input.sub_input(..=1).end_index(), 2);
        assert_eq!(bytes_input.sub_input(1..=1).end_index(), 2);
        assert_eq!(bytes_input.sub_input(1..).end_index(), 3);
        assert_eq!(bytes_input.sub_input(..3).end_index(), 3);
    }
}
