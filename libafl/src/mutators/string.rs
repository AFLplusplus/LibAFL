//! Mutators for preserving string properties, which may be useful for certain targets which are primarily string-oriented.

use alloc::{rc::Rc, vec::Vec};

use libafl_bolts::{rands::Rand, Error, HasLen, Named};

use crate::{
    corpus::{CorpusId, HasTestcase, Testcase},
    inputs::{BytesInput, HasBytesVec},
    mutators::{rand_range, MutationResult, Mutator},
    stages::{
        mutational::{MutatedTransform, MutatedTransformPost},
        string::{
            PropertyRanges, StringPropertiesMetadata, StringPropertiesStage, SubpropertyRanges,
        },
    },
    state::{HasCorpus, HasMaxSize, HasMetadata, HasRand},
};

/// Input shape for string property-preserving mutations.
pub type UnicodeInput = (BytesInput, Rc<(PropertyRanges, SubpropertyRanges)>);

impl<S> MutatedTransform<BytesInput, S> for UnicodeInput
where
    S: HasCorpus<Input = BytesInput> + HasTestcase,
{
    type Post = Rc<(PropertyRanges, SubpropertyRanges)>;

    fn try_transform_from(
        base: &mut Testcase<BytesInput>,
        state: &S,
        _corpus_idx: CorpusId,
    ) -> Result<Self, Error> {
        let meta = base.metadata::<StringPropertiesMetadata>();
        if let Ok(meta) = meta {
            if let StringPropertiesMetadata::PropertyRanges { properties } = meta.clone() {
                let input = base.load_input(state.corpus())?.clone();
                return Ok((input, properties));
            }
        }
        Err(Error::key_not_found(
            "No usable StringPropertiesMetadata for the provided testcase.",
        ))
    }

    fn try_transform_into(self, _state: &S) -> Result<(BytesInput, Self::Post), Error> {
        Ok(self)
    }
}

impl<S> MutatedTransformPost<S> for Rc<(PropertyRanges, SubpropertyRanges)>
where
    S: HasCorpus<Input = BytesInput> + HasTestcase,
{
    fn post_exec(
        self,
        state: &mut S,
        _stage_idx: i32,
        corpus_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        // we already spent time computing these properties during mutation, so we can skip this later
        if let Some(corpus_idx) = corpus_idx {
            let mut testcase = state.testcase_mut(corpus_idx)?;
            testcase.add_metadata(StringPropertiesMetadata::PropertyRanges { properties: self });
        }
        Ok(())
    }
}

/// Mutator which retains the general property of a randomly selected range of bytes
#[derive(Debug, Default)]
pub struct StringPropertyPreservingMutator;

impl Named for StringPropertyPreservingMutator {
    fn name(&self) -> &str {
        "string-property-preserving"
    }
}

const MAX_CHARS: usize = 16;

impl<S> Mutator<UnicodeInput, S> for StringPropertyPreservingMutator
where
    S: HasRand + HasMaxSize,
{
    fn mutate(
        &mut self,
        state: &mut S,
        (input, ranges): &mut UnicodeInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let max_len = state.max_size();
        let idx = state.rand_mut().below(input.len() as u64) as usize;

        let relevant_group_count = ranges
            .0
            .iter()
            .filter(|(range, _)| range.0 <= idx && idx < range.1)
            .count();
        let group_idx = state.rand_mut().below(relevant_group_count as u64) as usize;

        let &(byte_range, prop) = ranges.0.iter().nth(group_idx).unwrap();

        let string = core::str::from_utf8(&input.bytes()[byte_range.0..byte_range.1])?;
        let char_count = string.chars().count();

        let replaced_chars = rand_range(state, char_count, MAX_CHARS);
        let chars_len = replaced_chars.end - replaced_chars.start;

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
            crate::stages::string::unicode_properties::BY_NAME[prop].1;
        let choices: u64 = mutation_destinations
            .iter()
            .map(|&(min, max)| (max - min + 1) as u64)
            .sum();

        let mut new_len = input.len() - (bytes_end - bytes_start);
        let mut new_bytes = Vec::new();

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
        *ranges = Rc::new(StringPropertiesStage::<S>::group_by_properties(
            core::str::from_utf8(input.bytes()).unwrap(),
        ));

        Ok(MutationResult::Mutated)
    }
}

/// Mutator which retains the specific byte range of a property of a randomly selected range of bytes
#[derive(Debug, Default)]
pub struct StringSubpropertyPreservingMutator;

impl Named for StringSubpropertyPreservingMutator {
    fn name(&self) -> &str {
        "string-subproperty-preserving"
    }
}

impl<S> Mutator<UnicodeInput, S> for StringSubpropertyPreservingMutator
where
    S: HasRand + HasMaxSize,
{
    fn mutate(
        &mut self,
        state: &mut S,
        (input, ranges): &mut UnicodeInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let max_len = state.max_size();
        let idx = state.rand_mut().below(input.len() as u64) as usize;

        let relevant_group_count = ranges
            .1
            .iter()
            .filter(|(range, _)| range.0 <= idx && idx < range.1)
            .count();
        let group_idx = state.rand_mut().below(relevant_group_count as u64) as usize;

        let &(byte_range, (subprop_start, subprop_end)) = ranges.1.iter().nth(group_idx).unwrap();

        let string = core::str::from_utf8(&input.bytes()[byte_range.0..byte_range.1])?;
        let char_count = string.chars().count();

        let replaced_chars = rand_range(state, char_count, MAX_CHARS);
        let chars_len = replaced_chars.end - replaced_chars.start;

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
        *ranges = Rc::new(StringPropertiesStage::<S>::group_by_properties(
            core::str::from_utf8(input.bytes()).unwrap(),
        ));

        Ok(MutationResult::Mutated)
    }
}

#[cfg(test)]
mod test {
    use libafl_bolts::rands::StdRand;

    use super::*;
    use crate::{
        corpus::InMemoryCorpus,
        stages::string::StringPropertiesStage,
        state::{NopState, StdState},
    };

    // a not-so-useful test for this
    #[test]
    fn mutate_hex() {
        let result: Result<(), Error> = (|| {
            let hex = "0123456789abcdef0123456789abcdef";
            let len = hex.chars().count();
            let property_ranges =
                StringPropertiesStage::<NopState<BytesInput>>::group_by_properties(hex);
            let bytes = BytesInput::from(hex.as_bytes());

            let mut mutator = StringPropertyPreservingMutator::default();

            let mut state = StdState::new(
                StdRand::with_seed(0),
                InMemoryCorpus::<BytesInput>::new(),
                InMemoryCorpus::new(),
                &mut (),
                &mut (),
            )?;

            let mut unicode_input = (bytes, Rc::new(property_ranges));
            for _ in 0..(1 << 12) {
                let _ = mutator.mutate(&mut state, &mut unicode_input, 0);
                let hex = core::str::from_utf8(unicode_input.0.bytes()).unwrap();
                println!("{hex:?}");
                assert_eq!(hex.chars().count(), len);
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
            let property_ranges =
                StringPropertiesStage::<NopState<BytesInput>>::group_by_properties(hex);
            let bytes = BytesInput::from(hex.as_bytes());

            let mut mutator = StringSubpropertyPreservingMutator::default();

            let mut state = StdState::new(
                StdRand::with_seed(0),
                InMemoryCorpus::<BytesInput>::new(),
                InMemoryCorpus::new(),
                &mut (),
                &mut (),
            )?;

            let mut unicode_input = (bytes, Rc::new(property_ranges));
            for _ in 0..(1 << 12) {
                let _ = mutator.mutate(&mut state, &mut unicode_input, 0);
                let hex = core::str::from_utf8(unicode_input.0.bytes()).unwrap();
                println!("{hex:?}");
                assert_eq!(hex.chars().count(), len);
            }

            Ok(())
        })();

        if let Err(e) = result {
            panic!("failed with error: {e}");
        }
    }
}
