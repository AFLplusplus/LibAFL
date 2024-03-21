//! Mutators for preserving string categories, which may be useful for certain targets which are primarily string-oriented.
use alloc::vec::Vec;
use core::{
    cmp::{Ordering, Reverse},
    ops::Range,
};

use libafl_bolts::{rands::Rand, Error, HasLen, Named};

use crate::{
    corpus::{CorpusId, HasTestcase, Testcase},
    inputs::{BytesInput, HasBytesVec},
    mutators::{rand_range, MutationResult, Mutator, Tokens},
    stages::{
        extract_metadata,
        mutational::{MutatedTransform, MutatedTransformPost},
        StringIdentificationMetadata,
    },
    state::{HasCorpus, HasMaxSize, HasMetadata, HasRand},
};

/// Unicode category data, as used by string analysis and mutators.
#[allow(unused)]
#[allow(missing_docs)]
#[allow(clippy::redundant_static_lifetimes)]
pub mod unicode_categories;

/// Input which contains the context necessary to perform unicode mutations
pub type UnicodeInput = (BytesInput, StringIdentificationMetadata);

impl<S> MutatedTransform<BytesInput, S> for UnicodeInput
where
    S: HasCorpus<Input = BytesInput> + HasTestcase,
{
    type Post = StringIdentificationMetadata;

    fn try_transform_from(base: &mut Testcase<BytesInput>, state: &S) -> Result<Self, Error> {
        let input = base.load_input(state.corpus())?.clone();
        let metadata = base.metadata::<StringIdentificationMetadata>().cloned()?;
        Ok((input, metadata))
    }

    fn try_transform_into(self, _state: &S) -> Result<(BytesInput, Self::Post), Error> {
        Ok(self)
    }
}

impl<S> MutatedTransformPost<S> for StringIdentificationMetadata
where
    S: HasTestcase,
{
    fn post_exec(self, state: &mut S, corpus_idx: Option<CorpusId>) -> Result<(), Error> {
        if let Some(corpus_idx) = corpus_idx {
            let mut tc = state.testcase_mut(corpus_idx)?;
            tc.add_metadata(self);
        }
        Ok(())
    }
}

const MAX_CHARS: usize = 16;

fn choose_start<R: Rand>(
    rand: &mut R,
    bytes: &[u8],
    meta: &StringIdentificationMetadata,
) -> Option<(usize, usize)> {
    let idx = rand.below(bytes.len() as u64) as usize;
    let mut options = Vec::new();
    for (start, range) in meta.ranges() {
        if idx
            .checked_sub(*start) // idx adjusted to start
            .and_then(|idx| (idx < range.len()).then(|| range[idx])) // idx in range
            .map_or(false, |r| r)
        {
            options.push((*start, range));
        }
    }
    match options.len() {
        0 => None,
        1 => Some((options[0].0, options[0].1.len())),
        _ => {
            // bias towards longer strings
            options.sort_by_cached_key(|(_, entries)| entries.count_ones());
            let selected = libafl_bolts::math::integer_sqrt(
                rand.below((options.len() * options.len()) as u64),
            ) as usize;
            Some((options[selected].0, options[selected].1.len()))
        }
    }
}

fn get_subcategory<T: Ord + Copy>(needle: T, haystack: &[(T, T)]) -> Option<(T, T)> {
    haystack
        .binary_search_by(|&(min, max)| match min.cmp(&needle) {
            Ordering::Less | Ordering::Equal => match needle.cmp(&max) {
                Ordering::Less | Ordering::Equal => Ordering::Equal,
                Ordering::Greater => Ordering::Less,
            },
            Ordering::Greater => Ordering::Greater,
        })
        .ok()
        .map(|idx| haystack[idx])
}

fn find_range<F: Fn(char) -> bool>(
    chars: &[(usize, char)],
    idx: usize,
    predicate: F,
) -> Range<usize> {
    // walk backwards and discover
    let start = chars[..idx]
        .iter()
        .rev()
        .take_while(|&&(_, c)| predicate(c))
        .last()
        .map_or(chars[idx].0, |&(i, _)| i);
    // walk forwards
    let end = chars[(idx + 1)..]
        .iter()
        .take_while(|&&(_, c)| predicate(c))
        .last()
        .map_or(chars[idx].0 + chars[idx].1.len_utf8(), |&(i, c)| {
            i + c.len_utf8()
        });

    start..end
}

fn choose_category_range<R: Rand>(
    rand: &mut R,
    string: &str,
) -> (Range<usize>, &'static [(u32, u32)]) {
    let chars = string.char_indices().collect::<Vec<_>>();
    let idx = rand.below(chars.len() as u64) as usize;
    let c = chars[idx].1;

    // figure out the categories for this char
    let expanded = c as u32;
    #[cfg(test)]
    let mut names = Vec::new();
    let mut categories = Vec::new();
    for (_name, category) in unicode_categories::BY_NAME {
        if get_subcategory(expanded, category).is_some() {
            #[cfg(test)]
            names.push(_name);
            categories.push(category);
        }
    }

    // ok -- we want to bias towards smaller regions to keep the mutations "tight" to original
    // we sort the options by descending length, then pick isqrt of below(n^2)

    categories.sort_by_cached_key(|cat| {
        Reverse(
            cat.iter()
                .map(|&(min, max)| (max - min + 1) as usize)
                .sum::<usize>(),
        )
    });
    let options = categories.len() * categories.len();
    let selected_idx = libafl_bolts::math::integer_sqrt(rand.below(options as u64)) as usize;

    let selected = categories[selected_idx];

    #[cfg(test)]
    println!("category for `{c}' ({}): {}", c as u32, names[selected_idx]);

    (
        find_range(&chars, idx, |c| {
            get_subcategory(c as u32, selected).is_some()
        }),
        selected,
    )
}

fn choose_subcategory_range<R: Rand>(rand: &mut R, string: &str) -> (Range<usize>, (u32, u32)) {
    let chars = string.char_indices().collect::<Vec<_>>();
    let idx = rand.below(chars.len() as u64) as usize;
    let c = chars[idx].1;

    // figure out the categories for this char
    let expanded = c as u32;
    #[cfg(test)]
    let mut names = Vec::new();
    let mut subcategories = Vec::new();
    for (_name, category) in unicode_categories::BY_NAME {
        if let Some(subcategory) = get_subcategory(expanded, category) {
            #[cfg(test)]
            names.push(_name);
            subcategories.push(subcategory);
        }
    }

    // see reasoning for selection pattern in choose_category_range

    subcategories.sort_by_key(|&(min, max)| Reverse(max - min + 1));
    let options = subcategories.len() * subcategories.len();
    let selected_idx = libafl_bolts::math::integer_sqrt(rand.below(options as u64)) as usize;
    let selected = subcategories[selected_idx];

    #[cfg(test)]
    println!(
        "subcategory for `{c}' ({}): {} ({:?})",
        c as u32, names[selected_idx], selected
    );

    (
        find_range(&chars, idx, |c| {
            let expanded = c as u32;
            selected.0 <= expanded && expanded <= selected.1
        }),
        selected,
    )
}

fn rand_replace_range<S: HasRand + HasMaxSize, F: Fn(&mut S) -> char>(
    state: &mut S,
    input: &mut UnicodeInput,
    range: Range<usize>,
    char_gen: F,
) -> MutationResult {
    let temp_range = rand_range(state, range.end - range.start, MAX_CHARS);
    let range = (range.start + temp_range.start)..(range.start + temp_range.end);
    let range = match core::str::from_utf8(&input.0.bytes()[range.clone()]) {
        Ok(_) => range,
        Err(e) => range.start..(range.start + e.valid_up_to()),
    };

    #[cfg(test)]
    println!(
        "mutating range: {:?} ({:?})",
        range,
        core::str::from_utf8(&input.0.bytes()[range.clone()])
    );
    if range.start == range.end {
        return MutationResult::Skipped;
    }

    let replace_len = state.rand_mut().below(MAX_CHARS as u64) as usize;
    let orig_len = range.end - range.start;
    if input.0.len() - orig_len + replace_len > state.max_size() {
        return MutationResult::Skipped;
    }

    let mut replacement = Vec::with_capacity(replace_len);
    let mut dest = [0u8; 4];

    loop {
        let new_c = char_gen(state);
        if replacement.len() + new_c.len_utf8() > replace_len {
            break;
        }
        new_c.encode_utf8(&mut dest);
        replacement.extend_from_slice(&dest[..new_c.len_utf8()]);
        if replacement.len() + new_c.len_utf8() == replace_len {
            break; // nailed it
        }
    }

    input.0.bytes_mut().splice(range, replacement);
    input.1 = extract_metadata(input.0.bytes());

    MutationResult::Mutated
}

/// Mutator which randomly replaces a randomly selected range of bytes with bytes that preserve the
/// range's category
#[derive(Debug, Default)]
pub struct StringCategoryRandMutator;

impl Named for StringCategoryRandMutator {
    fn name(&self) -> &str {
        "string-category-rand"
    }
}

impl<S> Mutator<UnicodeInput, S> for StringCategoryRandMutator
where
    S: HasRand + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut UnicodeInput) -> Result<MutationResult, Error> {
        if input.0.bytes().is_empty() {
            return Ok(MutationResult::Skipped);
        }

        let bytes = input.0.bytes();
        let meta = &input.1;
        if let Some((base, len)) = choose_start(state.rand_mut(), bytes, meta) {
            let substring = core::str::from_utf8(&bytes[base..][..len])?;
            let (range, category) = choose_category_range(state.rand_mut(), substring);
            #[cfg(test)]
            println!(
                "{:?} => {:?}",
                range,
                core::str::from_utf8(&bytes[range.clone()])
            );

            let options: u64 = category
                .iter()
                .map(|&(start, end)| u64::from(end) - u64::from(start) + 1)
                .sum();
            let char_gen = |state: &mut S| loop {
                let mut selected = state.rand_mut().below(options);
                for &(min, max) in category {
                    if let Some(next_selected) =
                        selected.checked_sub(u64::from(max) - u64::from(min) + 1)
                    {
                        selected = next_selected;
                    } else if let Some(new_c) = char::from_u32(selected as u32 + min) {
                        return new_c;
                    } else {
                        break;
                    }
                }
            };

            return Ok(rand_replace_range(state, input, range, char_gen));
        }

        Ok(MutationResult::Skipped)
    }
}

/// Mutator which randomly replaces a randomly selected range of bytes with bytes that preserve the
/// range's subcategory
#[derive(Debug, Default)]
pub struct StringSubcategoryRandMutator;

impl Named for StringSubcategoryRandMutator {
    fn name(&self) -> &str {
        "string-subcategory-rand"
    }
}

impl<S> Mutator<UnicodeInput, S> for StringSubcategoryRandMutator
where
    S: HasRand + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut UnicodeInput) -> Result<MutationResult, Error> {
        if input.0.bytes().is_empty() {
            return Ok(MutationResult::Skipped);
        }

        let bytes = input.0.bytes();
        let meta = &input.1;
        if let Some((base, len)) = choose_start(state.rand_mut(), bytes, meta) {
            let substring = core::str::from_utf8(&bytes[base..][..len])?;
            let (range, subcategory) = choose_subcategory_range(state.rand_mut(), substring);
            #[cfg(test)]
            println!(
                "{:?} => {:?}",
                range,
                core::str::from_utf8(&bytes[range.clone()])
            );

            let options: u64 = u64::from(subcategory.1) - u64::from(subcategory.0) + 1;
            let char_gen = |state: &mut S| loop {
                let selected = state.rand_mut().below(options);
                if let Some(new_c) = char::from_u32(selected as u32 + subcategory.0) {
                    return new_c;
                }
            };

            return Ok(rand_replace_range(state, input, range, char_gen));
        }

        Ok(MutationResult::Skipped)
    }
}

/// Mutator which randomly replaces a full category-contiguous region of chars with a random token
#[derive(Debug, Default)]
pub struct StringCategoryTokenReplaceMutator;

impl Named for StringCategoryTokenReplaceMutator {
    fn name(&self) -> &str {
        "string-category-token-replace"
    }
}

impl<S> Mutator<UnicodeInput, S> for StringCategoryTokenReplaceMutator
where
    S: HasRand + HasMaxSize + HasMetadata,
{
    fn mutate(&mut self, state: &mut S, input: &mut UnicodeInput) -> Result<MutationResult, Error> {
        if input.0.bytes().is_empty() {
            return Ok(MutationResult::Skipped);
        }

        let tokens_len = {
            let Some(meta) = state.metadata_map().get::<Tokens>() else {
                return Ok(MutationResult::Skipped);
            };
            if meta.tokens().is_empty() {
                return Ok(MutationResult::Skipped);
            }
            meta.tokens().len()
        };
        let token_idx = state.rand_mut().below(tokens_len as u64) as usize;

        let bytes = input.0.bytes();
        let meta = &input.1;
        if let Some((base, len)) = choose_start(state.rand_mut(), bytes, meta) {
            let substring = core::str::from_utf8(&bytes[base..][..len])?;
            let (range, _) = choose_category_range(state.rand_mut(), substring);

            #[cfg(test)]
            println!(
                "{:?} => {:?}",
                range,
                core::str::from_utf8(&bytes[range.clone()])
            );

            let meta = state.metadata_map().get::<Tokens>().unwrap();
            let token = &meta.tokens()[token_idx];

            if input.0.len() - (range.end - range.start) + token.len() > state.max_size() {
                return Ok(MutationResult::Skipped);
            }

            input.0.bytes_mut().splice(range, token.iter().copied());
            input.1 = extract_metadata(input.0.bytes());
            return Ok(MutationResult::Mutated);
        }

        Ok(MutationResult::Skipped)
    }
}

/// Mutator which randomly replaces a full subcategory-contiguous region of chars with a random token
#[derive(Debug, Default)]
pub struct StringSubcategoryTokenReplaceMutator;

impl Named for StringSubcategoryTokenReplaceMutator {
    fn name(&self) -> &str {
        "string-subcategory-replace"
    }
}

impl<S> Mutator<UnicodeInput, S> for StringSubcategoryTokenReplaceMutator
where
    S: HasRand + HasMaxSize + HasMetadata,
{
    fn mutate(&mut self, state: &mut S, input: &mut UnicodeInput) -> Result<MutationResult, Error> {
        if input.0.bytes().is_empty() {
            return Ok(MutationResult::Skipped);
        }

        let tokens_len = {
            let Some(meta) = state.metadata_map().get::<Tokens>() else {
                return Ok(MutationResult::Skipped);
            };
            if meta.tokens().is_empty() {
                return Ok(MutationResult::Skipped);
            }
            meta.tokens().len()
        };
        let token_idx = state.rand_mut().below(tokens_len as u64) as usize;

        let bytes = input.0.bytes();
        let meta = &input.1;
        if let Some((base, len)) = choose_start(state.rand_mut(), bytes, meta) {
            let substring = core::str::from_utf8(&bytes[base..][..len])?;
            let (range, _) = choose_subcategory_range(state.rand_mut(), substring);

            #[cfg(test)]
            println!(
                "{:?} => {:?}",
                range,
                core::str::from_utf8(&bytes[range.clone()])
            );

            let meta = state.metadata_map().get::<Tokens>().unwrap();
            let token = &meta.tokens()[token_idx];

            if input.0.len() - (range.end - range.start) + token.len() > state.max_size() {
                return Ok(MutationResult::Skipped);
            }

            input.0.bytes_mut().splice(range, token.iter().copied());
            input.1 = extract_metadata(input.0.bytes());
            return Ok(MutationResult::Mutated);
        }

        Ok(MutationResult::Skipped)
    }
}

#[cfg(test)]
mod test {
    use libafl_bolts::{rands::StdRand, Error};

    use crate::{
        corpus::NopCorpus,
        inputs::{BytesInput, HasBytesVec},
        mutators::{Mutator, StringCategoryRandMutator, StringSubcategoryRandMutator},
        stages::extract_metadata,
        state::StdState,
    };

    // a not-so-useful test for this
    #[test]
    fn mutate_hex() {
        let result: Result<(), Error> = (|| {
            let hex = "0123456789abcdef0123456789abcdef";
            let mut bytes = BytesInput::from(hex.as_bytes());

            let mut mutator = StringCategoryRandMutator;

            let mut state = StdState::new(
                StdRand::with_seed(0),
                NopCorpus::<BytesInput>::new(),
                NopCorpus::new(),
                &mut (),
                &mut (),
            )?;

            for _ in 0..(1 << 12) {
                let metadata = extract_metadata(bytes.bytes());
                let mut input = (bytes, metadata);
                let _ = mutator.mutate(&mut state, &mut input);
                println!("{:?}", core::str::from_utf8(input.0.bytes()).unwrap());
                bytes = input.0;
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
            let mut bytes = BytesInput::from(hex.as_bytes());

            let mut mutator = StringSubcategoryRandMutator;

            let mut state = StdState::new(
                StdRand::with_seed(0),
                NopCorpus::<BytesInput>::new(),
                NopCorpus::new(),
                &mut (),
                &mut (),
            )?;

            for _ in 0..(1 << 12) {
                let metadata = extract_metadata(bytes.bytes());
                let mut input = (bytes, metadata);
                let _ = mutator.mutate(&mut state, &mut input);
                println!("{:?}", core::str::from_utf8(input.0.bytes()).unwrap());
                bytes = input.0;
            }

            Ok(())
        })();

        if let Err(e) = result {
            panic!("failed with error: {e}");
        }
    }
}
