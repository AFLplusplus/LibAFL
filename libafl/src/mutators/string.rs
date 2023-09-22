//! Mutators for preserving string categories, which may be useful for certain targets which are primarily string-oriented.

use alloc::{rc::Rc, vec::Vec};

use libafl_bolts::{rands::Rand, Error, HasLen, Named};

use crate::{
    corpus::{CorpusId, HasTestcase, Testcase},
    inputs::{BytesInput, HasBytesVec},
    mutators::{rand_range, MutationResult, Mutator, Tokens},
    stages::{
        mutational::{MutatedTransform, MutatedTransformPost},
        string::{
            CategoryRanges, StringCategoriesStage, StringCategoryMetadata, SubcategoryRanges,
        },
    },
    state::{HasCorpus, HasMaxSize, HasMetadata, HasRand},
};

/// Input shape for string category-preserving mutations.
pub type UnicodeInput = (BytesInput, (Rc<(CategoryRanges, SubcategoryRanges)>, bool));

impl<S> MutatedTransform<BytesInput, S> for UnicodeInput
where
    S: HasCorpus<Input = BytesInput> + HasTestcase,
{
    type Post = (Rc<(CategoryRanges, SubcategoryRanges)>, bool);

    fn try_transform_from(
        base: &mut Testcase<BytesInput>,
        state: &S,
        _corpus_idx: CorpusId,
    ) -> Result<Self, Error> {
        let meta = base.metadata::<StringCategoryMetadata>();
        if let Ok(meta) = meta {
            if let StringCategoryMetadata::CategoryRanges { categories } = meta.clone() {
                let input = base.load_input(state.corpus())?.clone();
                return Ok((input, (categories, true)));
            }
        }
        Err(Error::key_not_found(
            "No usable StringCategoriesMetadata for the provided testcase.",
        ))
    }

    fn try_transform_into(self, _state: &S) -> Result<(BytesInput, Self::Post), Error> {
        Ok(self)
    }
}

impl<S> MutatedTransformPost<S> for (Rc<(CategoryRanges, SubcategoryRanges)>, bool)
where
    S: HasCorpus<Input = BytesInput> + HasTestcase,
{
    fn post_exec(
        self,
        state: &mut S,
        _stage_idx: i32,
        corpus_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        let (categories, preserve) = self;
        if preserve {
            // we already spent time computing these categories during mutation, so we can skip this later
            if let Some(corpus_idx) = corpus_idx {
                let mut testcase = state.testcase_mut(corpus_idx)?;
                testcase.add_metadata(StringCategoryMetadata::CategoryRanges { categories });
            }
        }
        Ok(())
    }
}

/// Mutator which retains the general category of a randomly selected range of bytes
#[derive(Debug, Default)]
pub struct StringCategoryPreservingMutator<const STACKING: bool>;

impl<const STACKING: bool> Named for StringCategoryPreservingMutator<STACKING> {
    fn name(&self) -> &str {
        "string-category-preserving"
    }
}

const MAX_CHARS: usize = 16;

impl<S, const STACKING: bool> Mutator<UnicodeInput, S> for StringCategoryPreservingMutator<STACKING>
where
    S: HasRand + HasMaxSize,
{
    fn mutate(
        &mut self,
        state: &mut S,
        (input, (ranges, preserve)): &mut UnicodeInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let max_len = state.max_size();
        let idx = state.rand_mut().below(input.len() as u64) as usize;

        let relevant_group_count = ranges
            .0
            .iter()
            .filter(|(range, _)| range.0 <= idx && idx < range.1)
            .count();
        if relevant_group_count == 0 {
            return Ok(MutationResult::Skipped);
        }
        let group_idx = state.rand_mut().below(relevant_group_count as u64) as usize;

        let &(byte_range, cat) = ranges
            .0
            .iter()
            .filter(|(range, _)| range.0 <= idx && idx < range.1)
            .nth(group_idx)
            .unwrap();

        let string = core::str::from_utf8(&input.bytes()[byte_range.0..byte_range.1])?;
        let char_count = string.chars().count();

        let replaced_chars = rand_range(state, char_count, MAX_CHARS);

        let (bytes_start, _) = string.char_indices().nth(replaced_chars.start).unwrap();
        let bytes_end = string
            .char_indices()
            .nth(replaced_chars.end)
            .map(|(i, _)| i)
            .unwrap_or_else(|| byte_range.1 - byte_range.0);

        let bytes_start = bytes_start + byte_range.0;
        let bytes_end = bytes_end + byte_range.0;

        let replaced_bytes = bytes_start..bytes_end;

        let mutation_destinations: &[(u32, u32)] =
            crate::stages::string::unicode_categories::BY_NAME[cat].1;
        let choices: u64 = mutation_destinations
            .iter()
            .map(|&(min, max)| (max - min + 1) as u64)
            .sum();

        let mut new_len = input.len() - (bytes_end - bytes_start);
        let mut new_bytes = Vec::new();

        let chars_len = state.rand_mut().below(MAX_CHARS as u64);

        let mut scratch = [0u8; 4];
        let mut i = 0;
        'outerloop: loop {
            if i >= chars_len {
                break;
            }
            let mut choice = state.rand_mut().below(choices);
            for &(subcat_start, subcat_end) in mutation_destinations {
                if let Some(next_choice) =
                    choice.checked_sub((subcat_end - subcat_start + 1) as u64)
                {
                    choice = next_choice;
                } else {
                    let c = subcat_start + choice as u32;
                    let Some(c) = char::from_u32(c) else {
                        // rare case: Rust disagrees with us on what is valid character!
                        continue 'outerloop;
                    };
                    let c_as_str = c.encode_utf8(&mut scratch);
                    let c_as_bytes = c_as_str.as_bytes();

                    if new_len + c_as_bytes.len() > max_len {
                        break 'outerloop;
                    }
                    new_len += c_as_bytes.len();

                    new_bytes.extend_from_slice(c_as_str.as_bytes());
                    break;
                }
            }
            i += 1;
        }

        input.bytes_mut().splice(replaced_bytes, new_bytes);

        if STACKING {
            *ranges = Rc::new(StringCategoriesStage::<S>::group_by_categories(
                core::str::from_utf8(input.bytes()).unwrap(),
            ));
        } else {
            *preserve = false;
        }

        Ok(MutationResult::Mutated)
    }
}

/// Mutator which retains the specific byte range of a category of a randomly selected range of bytes
#[derive(Debug, Default)]
pub struct StringSubcategoryPreservingMutator<const STACKING: bool>;

impl<const STACKING: bool> Named for StringSubcategoryPreservingMutator<STACKING> {
    fn name(&self) -> &str {
        "string-subcategory-preserving"
    }
}

impl<S, const STACKING: bool> Mutator<UnicodeInput, S>
    for StringSubcategoryPreservingMutator<STACKING>
where
    S: HasRand + HasMaxSize,
{
    fn mutate(
        &mut self,
        state: &mut S,
        (input, (ranges, preserve)): &mut UnicodeInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let max_len = state.max_size();
        let idx = state.rand_mut().below(input.len() as u64) as usize;

        let relevant_group_count = ranges
            .1
            .iter()
            .filter(|(range, _)| range.0 <= idx && idx < range.1)
            .count();
        if relevant_group_count == 0 {
            return Ok(MutationResult::Skipped);
        }
        let group_idx = state.rand_mut().below(relevant_group_count as u64) as usize;

        let &(byte_range, (subcat_start, subcat_end)) = ranges
            .1
            .iter()
            .filter(|(range, _)| range.0 <= idx && idx < range.1)
            .nth(group_idx)
            .unwrap();

        let string = core::str::from_utf8(&input.bytes()[byte_range.0..byte_range.1])?;
        let char_count = string.chars().count();

        let replaced_chars = rand_range(state, char_count, MAX_CHARS);

        let (bytes_start, _) = string.char_indices().nth(replaced_chars.start).unwrap();
        let bytes_end = string
            .char_indices()
            .nth(replaced_chars.end)
            .map(|(i, _)| i)
            .unwrap_or_else(|| byte_range.1 - byte_range.0);

        let bytes_start = bytes_start + byte_range.0;
        let bytes_end = bytes_end + byte_range.0;

        let replaced_bytes = bytes_start..bytes_end;

        let mut new_len = input.len() - (bytes_end - bytes_start);
        let mut new_bytes = Vec::new();

        let chars_len = state.rand_mut().below(MAX_CHARS as u64);

        let mut scratch = [0u8; 4];
        let mut i = 0;
        loop {
            if i >= chars_len {
                break;
            }
            let choice = state
                .rand_mut()
                .below((subcat_end - subcat_start) as u64 + 1) as u32;
            let c = subcat_start + choice;
            let Some(c) = char::from_u32(c) else {
                // rare case: Rust disagrees with us on what is valid character!
                continue;
            };
            let c_as_str = c.encode_utf8(&mut scratch);
            let c_as_bytes = c_as_str.as_bytes();

            if new_len + c_as_bytes.len() > max_len {
                break;
            }
            new_len += c_as_bytes.len();

            new_bytes.extend_from_slice(c_as_str.as_bytes());
            i += 1;
        }

        input.bytes_mut().splice(replaced_bytes, new_bytes);

        if STACKING {
            *ranges = Rc::new(StringCategoriesStage::<S>::group_by_categories(
                core::str::from_utf8(input.bytes()).unwrap(),
            ));
        } else {
            *preserve = false;
        }

        Ok(MutationResult::Mutated)
    }
}

/// Mutator which randomly replaces a full category-contiguous region of chars with a random token
#[derive(Debug, Default)]
pub struct StringCategoryReplaceMutator<const STACKING: bool>;

impl<const STACKING: bool> Named for StringCategoryReplaceMutator<STACKING> {
    fn name(&self) -> &str {
        "string-category-replace"
    }
}

impl<S, const STACKING: bool> Mutator<UnicodeInput, S> for StringCategoryReplaceMutator<STACKING>
where
    S: HasRand + HasMaxSize + HasMetadata,
{
    fn mutate(
        &mut self,
        state: &mut S,
        (input, (ranges, preserve)): &mut UnicodeInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let tokens_len = {
            let meta = state.metadata_map().get::<Tokens>();
            if meta.is_none() {
                return Ok(MutationResult::Skipped);
            }
            if meta.unwrap().tokens().is_empty() {
                return Ok(MutationResult::Skipped);
            }
            meta.unwrap().tokens().len()
        };
        let token_idx = state.rand_mut().below(tokens_len as u64) as usize;

        let max_len = state.max_size();
        let idx = state.rand_mut().below(input.len() as u64) as usize;

        let relevant_group_count = ranges
            .0
            .iter()
            .filter(|(range, _)| range.0 <= idx && idx < range.1)
            .count();
        if relevant_group_count == 0 {
            return Ok(MutationResult::Skipped);
        }
        let group_idx = state.rand_mut().below(relevant_group_count as u64) as usize;

        let &(byte_range, _) = ranges
            .0
            .iter()
            .filter(|(range, _)| range.0 <= idx && idx < range.1)
            .nth(group_idx)
            .unwrap();

        let meta = state.metadata_map().get::<Tokens>().unwrap();
        let token = &meta.tokens()[token_idx];

        // sanity: must be a string when we're done
        if core::str::from_utf8(token).is_err() {
            return Ok(MutationResult::Skipped);
        }

        if input.len() - (byte_range.1 - byte_range.0) + token.len() > max_len {
            return Ok(MutationResult::Skipped);
        }

        input
            .bytes_mut()
            .splice(byte_range.0..byte_range.1, token.iter().copied());

        if STACKING {
            *ranges = Rc::new(StringCategoriesStage::<S>::group_by_categories(
                core::str::from_utf8(input.bytes()).unwrap(),
            ));
        } else {
            *preserve = false;
        }

        Ok(MutationResult::Mutated)
    }
}

/// Mutator which randomly replaces a full subcategory-contiguous region of chars with a random token
#[derive(Debug, Default)]
pub struct StringSubcategoryReplaceMutator<const STACKING: bool>;

impl<const STACKING: bool> Named for StringSubcategoryReplaceMutator<STACKING> {
    fn name(&self) -> &str {
        "string-subcategory-replace"
    }
}

impl<S, const STACKING: bool> Mutator<UnicodeInput, S> for StringSubcategoryReplaceMutator<STACKING>
where
    S: HasRand + HasMaxSize + HasMetadata,
{
    fn mutate(
        &mut self,
        state: &mut S,
        (input, (ranges, preserve)): &mut UnicodeInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let tokens_len = {
            let meta = state.metadata_map().get::<Tokens>();
            if meta.is_none() {
                return Ok(MutationResult::Skipped);
            }
            if meta.unwrap().tokens().is_empty() {
                return Ok(MutationResult::Skipped);
            }
            meta.unwrap().tokens().len()
        };
        let token_idx = state.rand_mut().below(tokens_len as u64) as usize;

        let max_len = state.max_size();
        let idx = state.rand_mut().below(input.len() as u64) as usize;

        let relevant_group_count = ranges
            .1
            .iter()
            .filter(|(range, _)| range.0 <= idx && idx < range.1)
            .count();
        if relevant_group_count == 0 {
            return Ok(MutationResult::Skipped);
        }
        let group_idx = state.rand_mut().below(relevant_group_count as u64) as usize;

        let &(byte_range, _) = ranges
            .1
            .iter()
            .filter(|(range, _)| range.0 <= idx && idx < range.1)
            .nth(group_idx)
            .unwrap();

        let meta = state.metadata_map().get::<Tokens>().unwrap();
        let token = &meta.tokens()[token_idx];

        // sanity: must be a string when we're done
        if core::str::from_utf8(token).is_err() {
            return Ok(MutationResult::Skipped);
        }

        if input.len() - (byte_range.1 - byte_range.0) + token.len() > max_len {
            return Ok(MutationResult::Skipped);
        }

        input
            .bytes_mut()
            .splice(byte_range.0..byte_range.1, token.iter().copied());

        if STACKING {
            *ranges = Rc::new(StringCategoriesStage::<S>::group_by_categories(
                core::str::from_utf8(input.bytes()).unwrap(),
            ));
        } else {
            *preserve = false;
        }

        Ok(MutationResult::Mutated)
    }
}

#[cfg(test)]
mod test {
    use libafl_bolts::rands::StdRand;

    use super::*;
    use crate::{
        corpus::InMemoryCorpus,
        stages::string::StringCategoriesStage,
        state::{NopState, StdState},
    };

    // a not-so-useful test for this
    #[test]
    fn mutate_hex() {
        let result: Result<(), Error> = (|| {
            let hex = "0123456789abcdef0123456789abcdef";
            let len = hex.chars().count();
            let category_ranges =
                StringCategoriesStage::<NopState<BytesInput>>::group_by_categories(hex);
            let bytes = BytesInput::from(hex.as_bytes());

            let mut mutator = StringCategoryPreservingMutator::<true>;

            let mut state = StdState::new(
                StdRand::with_seed(0),
                InMemoryCorpus::<BytesInput>::new(),
                InMemoryCorpus::new(),
                &mut (),
                &mut (),
            )?;

            let mut unicode_input = (bytes, Rc::new(category_ranges));
            for _ in 0..(1 << 12) {
                let _ = mutator.mutate(&mut state, &mut unicode_input, 0);
                let hex = core::str::from_utf8(unicode_input.0.bytes()).unwrap();
                println!("{hex:?}");
            }

            Ok(())
        })();

        if let Err(e) = result {
            panic!("failed with error: {e}");
        }
    }

    #[test]
    fn mutate_hex_subcat() {
        let result: Result<(), Error> = (|| {
            let hex = "0123456789abcdef0123456789abcdef";
            let len = hex.chars().count();
            let category_ranges =
                StringCategoriesStage::<NopState<BytesInput>>::group_by_categories(hex);
            let bytes = BytesInput::from(hex.as_bytes());

            let mut mutator = StringSubcategoryPreservingMutator::<true>;

            let mut state = StdState::new(
                StdRand::with_seed(0),
                InMemoryCorpus::<BytesInput>::new(),
                InMemoryCorpus::new(),
                &mut (),
                &mut (),
            )?;

            let mut unicode_input = (bytes, Rc::new(category_ranges));
            for _ in 0..(1 << 12) {
                let _ = mutator.mutate(&mut state, &mut unicode_input, 0);
                let hex = core::str::from_utf8(unicode_input.0.bytes()).unwrap();
                println!("{hex:?}");
            }

            Ok(())
        })();

        if let Err(e) = result {
            panic!("failed with error: {e}");
        }
    }
}
