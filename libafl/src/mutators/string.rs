//! Mutators for preserving string categories, which may be useful for certain targets which are primarily string-oriented.
use alloc::vec::Vec;
use core::{cmp::Ordering, ops::Range};

use libafl_bolts::{rands::Rand, Error, HasLen, Named};

use crate::{
    inputs::{BytesInput, HasBytesVec},
    mutators::{rand_range, MutationResult, Mutator, Tokens},
    state::{HasMaxSize, HasMetadata, HasRand},
};

/// Unicode category data, as used by string analysis and mutators.
pub mod unicode_categories {
    #![allow(unused)]
    #![allow(missing_docs)]

    include!(concat!(env!("OUT_DIR"), "/unicode_categories.rs"));
}

/// Mutator which retains the general category of a randomly selected range of bytes
#[derive(Debug, Default)]
pub struct StringCategoryPreservingMutator;

impl Named for StringCategoryPreservingMutator {
    fn name(&self) -> &str {
        "string-category-preserving"
    }
}

const MAX_CHARS: usize = 16;

fn choose_index<R: Rand>(rand: &mut R, bytes: &[u8]) -> Option<(char, usize)> {
    if bytes.is_empty() {
        None
    } else {
        let idx = rand.below(bytes.len() as u64);
        let mut indices = (idx.saturating_sub(3)..=idx).rev();

        // try to find a character between [idx-3, idx+4)
        let (c, idx, max_idx) = 'outerloop: loop {
            if let Some(idx) = indices.next() {
                let idx = idx as usize;
                for max_idx in (idx + 1)..=(idx + 3).min(bytes.len()) {
                    if let Ok(string) = core::str::from_utf8(&bytes[idx..max_idx]) {
                        // we found a valid character
                        break 'outerloop (string.chars().next().unwrap(), idx, max_idx);
                    }
                }
            } else {
                return None;
            }
        };
        debug_assert!(idx + c.len_utf8() == max_idx);

        Some((c, idx))
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
    bytes: &[u8],
    c: char,
    idx: usize,
    predicate: F,
) -> Range<usize> {
    // walk backwards and discover
    let max_idx = idx + c.len_utf8();
    let mut backtracking = 0;
    let mut curr_start = idx;
    let mut curr_max = max_idx;
    let mut start_iter = (0..idx).rev();
    let start = loop {
        if let Some(maybe_start) = start_iter.next() {
            if let Ok(string) = core::str::from_utf8(&bytes[maybe_start..curr_max]) {
                if let Some(first) = string.char_indices().next() {
                    if let Some(last) = string.char_indices().next() {
                        if curr_max == last.0 + last.1.len_utf8() && c == last.1 {
                            if predicate(first.1) {
                                curr_start = first.0;
                                curr_max = last.0;
                            }
                        }
                    }
                }
            }
            backtracking += 1;
            if backtracking >= 4 {
                break curr_start;
            }
        } else {
            break curr_start; // it's the beginning!
        }
    };

    let valid_str = match core::str::from_utf8(&bytes[start..]).map_err(|e| e.valid_up_to()) {
        Ok(s) => s,
        Err(end) => core::str::from_utf8(&bytes[start..][..end]).unwrap(),
    };
    let mut potentials = valid_str.char_indices().skip_while(|&(i, _c)| i <= idx);
    let end = loop {
        if let Some((i, c)) = potentials.next() {
            if !predicate(c) {
                break i + start;
            }
        } else {
            break bytes.len();
        }
    };

    start..end
}

fn choose_category_range<R: Rand>(
    rand: &mut R,
    bytes: &[u8],
    c: char,
    idx: usize,
) -> Option<(Range<usize>, &'static [(u32, u32)])> {
    // figure out the categories for this char
    let expanded = c as u32;
    #[cfg(test)]
    let mut names = Vec::new();
    let mut categories = Vec::new();
    for (_name, category) in unicode_categories::BY_NAME.iter() {
        #[cfg(test)]
        names.push(_name);
        if get_subcategory(expanded, category).is_some() {
            categories.push(category);
        }
    }

    // ok -- we want to bias towards smaller regions to keep the mutations "tight" to original
    // we sort the options by descending length, then pick isqrt of below(n^2)

    categories.sort_by_cached_key(|cat| {
        usize::MAX
            - cat
                .iter()
                .map(|&(min, max)| (max - min + 1) as usize)
                .sum::<usize>()
    });
    let options = categories.len() * categories.len();
    let selected_idx = libafl_bolts::math::integer_sqrt(rand.below(options as u64)) as usize;

    let selected = categories[selected_idx];

    #[cfg(test)]
    println!("category: {}", names[selected_idx]);

    Some((
        find_range(bytes, c, idx, |c| {
            get_subcategory(c as u32, selected).is_some()
        }),
        selected,
    ))
}

fn choose_subcategory_range<R: Rand>(
    rand: &mut R,
    bytes: &[u8],
    c: char,
    idx: usize,
) -> Option<(Range<usize>, (u32, u32))> {
    // figure out the categories for this char
    let expanded = c as u32;
    #[cfg(test)]
    let mut names = Vec::new();
    let mut subcategories = Vec::new();
    for (_name, category) in unicode_categories::BY_NAME.iter() {
        #[cfg(test)]
        names.push(_name);
        if let Some(subcategory) = get_subcategory(expanded, category) {
            subcategories.push(subcategory);
        }
    }

    // see reasoning for selection pattern in choose_category_range

    subcategories.sort_by_key(|&(min, max)| max - min + 1);
    let options = subcategories.len() * subcategories.len();
    let selected_idx = libafl_bolts::math::integer_sqrt(rand.below(options as u64)) as usize;
    let selected = subcategories[selected_idx];

    #[cfg(test)]
    println!("subcategory: {} ({:?})", names[selected_idx], selected);

    Some((
        find_range(bytes, c, idx, |c| {
            let expanded = c as u32;
            selected.0 <= expanded && expanded <= selected.1
        }),
        selected,
    ))
}

fn mutate_range<S: HasRand + HasMaxSize, F: Fn(&mut S) -> char>(
    state: &mut S,
    input: &mut BytesInput,
    range: Range<usize>,
    char_gen: F,
) -> Result<MutationResult, Error> {
    let temp_range = rand_range(state, range.end - range.start, MAX_CHARS);
    let range = (range.start + temp_range.start)..(range.start + temp_range.end);

    #[cfg(test)]
    println!(
        "{:?} => {:?}",
        range,
        core::str::from_utf8(&input.bytes()[range.clone()])
    );

    let replace_len = state.rand_mut().below(MAX_CHARS as u64) as usize;
    let orig_len = range.end - range.start;
    if input.len() - orig_len + replace_len > state.max_size() {
        return Ok(MutationResult::Skipped);
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

    input.bytes_mut().splice(range, replacement);

    return Ok(MutationResult::Mutated);
}

impl<S> Mutator<BytesInput, S> for StringCategoryPreservingMutator
where
    S: HasRand + HasMaxSize,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut BytesInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let bytes = input.bytes();
        if let Some((c, idx)) = choose_index(state.rand_mut(), bytes) {
            if let Some((range, category)) = choose_category_range(state.rand_mut(), bytes, c, idx)
            {
                #[cfg(test)]
                println!(
                    "{:?} => {:?}",
                    range,
                    core::str::from_utf8(&bytes[range.clone()])
                );

                let options: u64 = category
                    .iter()
                    .map(|&(start, end)| end as u64 - start as u64 + 1)
                    .sum();
                let char_gen = |state: &mut S| loop {
                    let mut selected = state.rand_mut().below(options);
                    let mut subcategories = category.iter();
                    while let Some(&(min, max)) = subcategories.next() {
                        if let Some(next_selected) =
                            selected.checked_sub(max as u64 - min as u64 + 1)
                        {
                            selected = next_selected;
                        } else if let Some(new_c) = char::from_u32(selected as u32 + min) {
                            return new_c;
                        } else {
                            break;
                        }
                    }
                };

                return mutate_range(state, input, range, char_gen);
            }
        }

        Ok(MutationResult::Skipped)
    }
}

/// Mutator which retains the specific byte range of a category of a randomly selected range of bytes
#[derive(Debug, Default)]
pub struct StringSubcategoryPreservingMutator;

impl Named for StringSubcategoryPreservingMutator {
    fn name(&self) -> &str {
        "string-subcategory-preserving"
    }
}

impl<S> Mutator<BytesInput, S> for StringSubcategoryPreservingMutator
where
    S: HasRand + HasMaxSize,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut BytesInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let bytes = input.bytes();
        if let Some((c, idx)) = choose_index(state.rand_mut(), bytes) {
            if let Some((range, subcategory)) =
                choose_subcategory_range(state.rand_mut(), bytes, c, idx)
            {
                #[cfg(test)]
                println!(
                    "{:?} => {:?}",
                    range,
                    core::str::from_utf8(&bytes[range.clone()])
                );

                let options: u64 = subcategory.1 as u64 - subcategory.0 as u64 + 1;
                let char_gen = |state: &mut S| loop {
                    let selected = state.rand_mut().below(options);
                    if let Some(new_c) = char::from_u32(selected as u32 + subcategory.0) {
                        return new_c;
                    }
                };

                return mutate_range(state, input, range, char_gen);
            }
        }

        Ok(MutationResult::Skipped)
    }
}

/// Mutator which randomly replaces a full category-contiguous region of chars with a random token
#[derive(Debug, Default)]
pub struct StringCategoryReplaceMutator;

impl Named for StringCategoryReplaceMutator {
    fn name(&self) -> &str {
        "string-category-replace"
    }
}

impl<S> Mutator<BytesInput, S> for StringCategoryReplaceMutator
where
    S: HasRand + HasMaxSize + HasMetadata,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut BytesInput,
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

        let bytes = input.bytes();
        if let Some((c, idx)) = choose_index(state.rand_mut(), bytes) {
            if let Some((range, _)) = choose_category_range(state.rand_mut(), bytes, c, idx) {
                #[cfg(test)]
                println!(
                    "{:?} => {:?}",
                    range,
                    core::str::from_utf8(&bytes[range.clone()])
                );

                let meta = state.metadata_map().get::<Tokens>().unwrap();
                let token = &meta.tokens()[token_idx];

                if input.len() - (range.end - range.start) + token.len() > state.max_size() {
                    return Ok(MutationResult::Skipped);
                }

                input.bytes_mut().splice(range, token.iter().copied());
                return Ok(MutationResult::Mutated);
            }
        }

        Ok(MutationResult::Skipped)
    }
}

/// Mutator which randomly replaces a full subcategory-contiguous region of chars with a random token
#[derive(Debug, Default)]
pub struct StringSubcategoryReplaceMutator;

impl Named for StringSubcategoryReplaceMutator {
    fn name(&self) -> &str {
        "string-subcategory-replace"
    }
}

impl<S> Mutator<BytesInput, S> for StringSubcategoryReplaceMutator
where
    S: HasRand + HasMaxSize + HasMetadata,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut BytesInput,
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

        let bytes = input.bytes();
        if let Some((c, idx)) = choose_index(state.rand_mut(), bytes) {
            if let Some((range, _)) = choose_subcategory_range(state.rand_mut(), bytes, c, idx) {
                #[cfg(test)]
                println!(
                    "{:?} => {:?}",
                    range,
                    core::str::from_utf8(&bytes[range.clone()])
                );

                let meta = state.metadata_map().get::<Tokens>().unwrap();
                let token = &meta.tokens()[token_idx];

                if input.len() - (range.end - range.start) + token.len() > state.max_size() {
                    return Ok(MutationResult::Skipped);
                }

                input.bytes_mut().splice(range, token.iter().copied());
                return Ok(MutationResult::Mutated);
            }
        }

        Ok(MutationResult::Skipped)
    }
}

#[cfg(test)]
mod test {
    use libafl_bolts::rands::StdRand;

    use super::*;
    use crate::{corpus::NopCorpus, state::StdState};

    // a not-so-useful test for this
    #[test]
    fn mutate_hex() {
        let result: Result<(), Error> = (|| {
            let hex = "0123456789abcdef0123456789abcdef";
            let mut bytes = BytesInput::from(hex.as_bytes());

            let mut mutator = StringCategoryPreservingMutator;

            let mut state = StdState::new(
                StdRand::with_seed(0),
                NopCorpus::<BytesInput>::new(),
                NopCorpus::new(),
                &mut (),
                &mut (),
            )?;

            for _ in 0..(1 << 12) {
                let _ = mutator.mutate(&mut state, &mut bytes, 0);
                if let Ok(hex) = core::str::from_utf8(bytes.bytes()) {
                    println!("{hex:?}");
                }
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

            let mut mutator = StringSubcategoryPreservingMutator;

            let mut state = StdState::new(
                StdRand::with_seed(0),
                NopCorpus::<BytesInput>::new(),
                NopCorpus::new(),
                &mut (),
                &mut (),
            )?;

            for _ in 0..(1 << 12) {
                let _ = mutator.mutate(&mut state, &mut bytes, 0);
                if let Ok(hex) = core::str::from_utf8(bytes.bytes()) {
                    println!("{hex:?}");
                }
            }

            Ok(())
        })();

        if let Err(e) = result {
            panic!("failed with error: {e}");
        }
    }
}
