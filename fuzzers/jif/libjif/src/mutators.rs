// TODO: comments on this file

use libafl::{
    bolts::{rands::Rand, tuples::Named},
    corpus::Corpus,
    inputs::{HasBytesVec, Input},
    mutators::{MutationResult, Mutator},
    prelude::{Tokens, UsesInput},
    state::{HasCorpus, HasMetadata, HasRand},
    Error,
};

/// Bytes delete mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct TagDeleteMutator;

impl<I, S> Mutator<S> for TagDeleteMutator
where
    I: Input + HasBytesVec,
    S: HasRand + UsesInput<Input = I>,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.bytes().len();
        if size <= 2 {
            return Ok(MutationResult::Skipped);
        }

        // we want to delete a tag, so we find offsets for < and > and delete one tag
        // first, collect all the offsets for < and >
        let mut starts = Vec::new();
        let mut ends = Vec::new();
        for (i, b) in input.bytes().iter().enumerate() {
            if *b == b'<' {
                starts.push(i);
            } else if *b == b'>' {
                ends.push(i);
            }
        }

        if starts.is_empty() || ends.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        // pick an offset randomly
        let idx: usize = state.rand_mut().below(starts.len().try_into().unwrap()) as usize;
        let start = starts[idx];
        // bounds check
        if idx >= ends.len() {
            return Ok(MutationResult::Skipped);
        }
        let end = ends[idx];

        if start > end || start > input.bytes().len() || end > input.bytes().len() {
            return Ok(MutationResult::Skipped);
        }

        //println!("original input: {}", String::from_utf8_lossy(input.bytes()));
        input.bytes_mut().drain(start..=end);
        //println!("trimmed input: {}", String::from_utf8_lossy(input.bytes()));

        Ok(MutationResult::Mutated)
    }
}

impl Named for TagDeleteMutator {
    fn name(&self) -> &str {
        "TagDeleteMutator"
    }
}

impl TagDeleteMutator {
    /// Creates a new [`BytesDeleteMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

// TagExpandMutator
// chooses a random tag within the test case and inserts it to a random location in the buffer
// that is after a >

/// Bytes delete mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct TagCopyMutator;

impl<I, S> Mutator<S> for TagCopyMutator
where
    I: Input + HasBytesVec,
    S: HasRand + UsesInput<Input = I>,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.bytes().len();
        if size <= 2 {
            return Ok(MutationResult::Skipped);
        }

        // we want to copy a tag to
        // first, collect all the offsets for < and >
        let mut starts = Vec::new();
        let mut ends = Vec::new();
        for (i, b) in input.bytes().iter().enumerate() {
            if *b == b'<' {
                starts.push(i);
            } else if *b == b'>' {
                ends.push(i);
            }
        }

        if starts.is_empty() || ends.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        // pick an offset randomly
        let idx: usize = state.rand_mut().below(starts.len().try_into().unwrap()) as usize;
        let start = starts[idx];
        // bounds check
        if idx >= ends.len() {
            return Ok(MutationResult::Skipped);
        }
        let end = ends[idx];

        if start > end || start > input.bytes().len() || end > input.bytes().len() {
            return Ok(MutationResult::Skipped);
        }
        let the_tag = input.bytes()[start..=end].to_vec();

        // now we need to find a > to insert the tag after
        let insertion_point =
            ends[state.rand_mut().below(ends.len().try_into().unwrap()) as usize] + 1;

        //println!("original input: {}", String::from_utf8_lossy(input.bytes()));
        // splice the tag in at insertion_point
        input
            .bytes_mut()
            .splice(insertion_point..insertion_point, the_tag);
        //println!("expanded input: {}", String::from_utf8_lossy(input.bytes()));
        Ok(MutationResult::Mutated)
    }
}

impl Named for TagCopyMutator {
    fn name(&self) -> &str {
        "TagCopyMutator"
    }
}

impl TagCopyMutator {
    /// Creates a new [`TagCopyMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

// TagCrossoverMutator
// chooses a random tag within the test case and inserts it to a random location in the buffer
// that is after a >

/// Bytes delete mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct TagCrossoverMutator;

impl<I, S> Mutator<S> for TagCrossoverMutator
where
    I: Input + HasBytesVec,
    S: HasRand + HasCorpus<Input = I>,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.bytes().len();
        if size <= 2 {
            return Ok(MutationResult::Skipped);
        }

        // we want to copy a tag to
        // first, collect all the offsets for < and >
        let mut starts = Vec::new();
        let mut ends = Vec::new();
        for (i, b) in input.bytes().iter().enumerate() {
            if *b == b'<' {
                starts.push(i);
            } else if *b == b'>' {
                ends.push(i);
            }
        }

        if starts.is_empty() || ends.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        // this should be a tag from a diff input

        // We don't want to use the testcase we're already using for splicing
        let count = state.corpus().count();
        let idx = state.rand_mut().below(count as u64) as usize;
        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
                return Ok(MutationResult::Skipped);
            }
        }
        let mut other_testcase = state.corpus().get(idx)?.borrow_mut().clone();
        let other_bytes = other_testcase.load_input()?.bytes();

        // pick a tag in other_bytes
        let mut other_starts = Vec::new();
        let mut other_ends = Vec::new();
        for (i, b) in other_bytes.iter().enumerate() {
            if *b == b'<' {
                other_starts.push(i);
            } else if *b == b'>' {
                other_ends.push(i);
            }
        }

        if other_starts.is_empty() || other_ends.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        // pick an offset randomly
        let the_rand = state.rand_mut();
        let idx: usize = the_rand.below(other_starts.len().try_into().unwrap()) as usize;
        let start = other_starts[idx];
        // bounds check
        if idx >= other_ends.len() {
            return Ok(MutationResult::Skipped);
        }
        let end = other_ends[idx];

        if start > end || start > other_bytes.len() || end > other_bytes.len() {
            return Ok(MutationResult::Skipped);
        }
        let the_tag = other_bytes[start..=end].to_vec();

        // now we need to find a > to insert the tag after
        let insertion_point = ends[the_rand.below(ends.len().try_into().unwrap()) as usize] + 1;

        // splice the tag in at insertion_point
        //println!("original input: {}", String::from_utf8_lossy(input.bytes()));
        input
            .bytes_mut()
            .splice(insertion_point..insertion_point, the_tag);
        //println!("expanded input: {}", String::from_utf8_lossy(input.bytes()));
        Ok(MutationResult::Mutated)
    }
}

impl Named for TagCrossoverMutator {
    fn name(&self) -> &str {
        "TagCrossoverMutator"
    }
}

impl TagCrossoverMutator {
    /// Creates a new [`TagCopyMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

// TagTokenMutator
// chooses a random token and inserts it to a random location in the buffer
// that is after a >
// idk what will happen if the token is not a tag

/// Bytes delete mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct TagTokenMutator;

impl<I, S> Mutator<S> for TagTokenMutator
where
    I: Input + HasBytesVec,
    S: HasRand + HasCorpus<Input = I> + HasMetadata,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.bytes().len();
        if size <= 2 {
            return Ok(MutationResult::Skipped);
        }

        // we want to copy a tag to
        // first, collect all the offsets for < and >
        let mut starts = Vec::new();
        let mut ends = Vec::new();
        for (i, b) in input.bytes().iter().enumerate() {
            if *b == b'<' {
                starts.push(i);
            } else if *b == b'>' {
                ends.push(i);
            }
        }

        if starts.is_empty() || ends.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        let tokens = state.metadata().clone();
        let tokens = tokens.get::<Tokens>();
        if tokens.is_none() {
            return Ok(MutationResult::Skipped);
        }
        let tokens = tokens.unwrap();
        let the_token =
            tokens.tokens()[state.rand_mut().below(tokens.len() as u64) as usize].clone();

        // now we need to find a > to insert the tag after
        let insertion_point = ends[state.rand_mut().below(ends.len() as u64) as usize] + 1;

        // splice the tag in at insertion_point
        //println!("original input: {}", String::from_utf8_lossy(input.bytes()));
        input
            .bytes_mut()
            .splice(insertion_point..insertion_point, the_token);
        //println!("expanded input: {}", String::from_utf8_lossy(input.bytes()));
        Ok(MutationResult::Mutated)
    }
}

impl Named for TagTokenMutator {
    fn name(&self) -> &str {
        "TagTokenMutator"
    }
}

impl TagTokenMutator {
    /// Creates a new [`TagTokenMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}
