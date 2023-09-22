//! Mutators for preserving string categories, which may be useful for certain targets which are primarily string-oriented.

use alloc::{rc::Rc, vec::Vec};

use libafl_bolts::{rands::Rand, Error, HasLen, Named};

use crate::{
    corpus::{CorpusId, HasTestcase, Testcase},
    inputs::{BytesInput, HasBytesVec},
    mutators::{rand_range, MutationResult, Mutator},
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

        let &(byte_range, prop) = ranges
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
            crate::stages::string::unicode_categories::BY_NAME[prop].1;
        let choices: u64 = mutation_destinations
            .iter()
            .map(|&(min, max)| (max - min + 1) as u64)
            .sum();

        let mut new_len = input.len() - (bytes_end - bytes_start);
        let mut new_bytes = Vec::new();

        let chars_len = state.rand_mut().below(MAX_CHARS as u64);

        let mut scratch = [0u8; 4];
        'outerloop: for _ in 0..chars_len {
            let mut choice = state.rand_mut().below(choices);
            for &(subprop_start, subprop_end) in mutation_destinations {
                if let Some(next_choice) =
                    choice.checked_sub((subprop_end - subprop_start + 1) as u64)
                {
                    choice = next_choice;
                } else {
                    let c = subprop_start + choice as u32;
                    let c = char::from_u32(c).unwrap();
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

        let &(byte_range, (subprop_start, subprop_end)) = ranges
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
        for _ in 0..chars_len {
            let choice = state
                .rand_mut()
                .below((subprop_end - subprop_start) as u64 + 1) as u32;
            let c = subprop_start + choice;
            let c = char::from_u32(c).unwrap();
            let c_as_str = c.encode_utf8(&mut scratch);
            let c_as_bytes = c_as_str.as_bytes();

            if new_len + c_as_bytes.len() > max_len {
                break;
            }
            new_len += c_as_bytes.len();

            new_bytes.extend_from_slice(c_as_str.as_bytes());
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
    fn mutate_hex_subprop() {
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
