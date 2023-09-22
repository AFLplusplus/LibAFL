//! Analysis of bytes-like inputs for string categories, which may be useful for certain targets which are primarily string-oriented.

use alloc::{collections::BTreeSet, rc::Rc, vec::Vec};
use core::{cmp::Ordering, marker::PhantomData};

use libafl_bolts::{impl_serdeany, Error};
use serde::{Deserialize, Serialize};

use crate::{
    corpus::{CorpusId, HasTestcase},
    inputs::{BytesInput, HasBytesVec, UsesInput},
    stages::Stage,
    state::{HasCorpus, HasMetadata, UsesState},
};

/// Unicode category data, as used by string analysis and mutators.
pub mod unicode_categories {
    #![allow(unused)]
    #![allow(missing_docs)]

    include!(concat!(env!("OUT_DIR"), "/unicode_categories.rs"));
}

/// A map from a range of bytes to an index into the unicode categories data.
pub type CategoryRange = ((usize, usize), usize);
/// All the ranges which share a common unicode category in a particular input.
pub type CategoryRanges = Vec<CategoryRange>;
/// A map from a range of bytes to an specific sub-range of a unicode category.
pub type SubcategoryRange = ((usize, usize), (u32, u32));
/// All the ranges which share a common unicode category byte range in a particular input.
pub type SubcategoryRanges = Vec<SubcategoryRange>;

/// The metadata representing the categories of a particular input.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum StringCategoryMetadata {
    /// The input could not be classified into categories (likely because it is not UTF-8).
    Unclassifiable,
    /// The input was classified.
    CategoryRanges {
        /// The ranges associated with the general categories and specific byte-ranges of general categories.
        categories: Rc<(CategoryRanges, SubcategoryRanges)>,
    },
}

impl_serdeany!(StringCategoryMetadata);

/// Stage which attaches [`StringCategoryMetadata`] to a testcase if it does not have it already.
#[derive(Debug)]
pub struct StringCategoriesStage<S> {
    phantom: PhantomData<S>,
}

impl<S> StringCategoriesStage<S> {
    /// Create a new copy of this stage.
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }

    pub(crate) fn group_by_categories(string: &str) -> (CategoryRanges, SubcategoryRanges) {
        let mut char_categories = vec![BTreeSet::new(); string.chars().count()];
        let mut all_categories = BTreeSet::new();

        let mut char_subcategories = vec![BTreeSet::new(); char_categories.len()];
        let mut all_subcategories = BTreeSet::new();
        for (prop, &(_, ranges)) in unicode_categories::BY_NAME.iter().enumerate() {
            // type inference help for IDEs
            let prop: usize = prop;
            let ranges: &'static [(u32, u32)] = ranges;

            let min = ranges.first().unwrap().0;
            let max = ranges.last().unwrap().1;

            for (c, (categories, subcategories)) in string.chars().zip(
                char_categories
                    .iter_mut()
                    .zip(char_subcategories.iter_mut()),
            ) {
                let value = c as u32;
                if min <= value && value <= max {
                    if let Ok(subprop) =
                        ranges.binary_search_by(|&(min, max)| match min.cmp(&value) {
                            Ordering::Less | Ordering::Equal => match value.cmp(&max) {
                                Ordering::Less | Ordering::Equal => Ordering::Equal,
                                Ordering::Greater => Ordering::Less,
                            },
                            Ordering::Greater => Ordering::Greater,
                        })
                    {
                        categories.insert(prop);
                        all_categories.insert(prop);
                        subcategories.insert(ranges[subprop]);
                        all_subcategories.insert(ranges[subprop]);
                    }
                }
            }
        }

        fn top_is_category<T: Copy + Eq + Ord>(props: &BTreeSet<T>, prop: T) -> bool {
            props.first().map_or(false, |&i| i == prop)
        }

        let mut prop_ranges = Vec::new();
        for curr_category in all_categories {
            let mut prop_iter = string.char_indices().zip(char_categories.iter_mut());
            loop {
                let mut prop_iter = (&mut prop_iter)
                    .skip_while(|(_, props)| !top_is_category(props, curr_category))
                    .take_while(|(_, props)| top_is_category(props, curr_category))
                    .map(|((i, c), props)| {
                        props.pop_first();
                        (i, c)
                    });
                if let Some((min, min_c)) = prop_iter.next() {
                    let (max, max_c) = prop_iter.last().unwrap_or((min, min_c));
                    prop_ranges.push(((min, max + max_c.len_utf8()), curr_category));
                } else {
                    break;
                }
            }
        }

        let mut subprop_ranges = Vec::new();
        for curr_subcategory in all_subcategories {
            let mut prop_iter = string.char_indices().zip(char_subcategories.iter_mut());
            loop {
                let mut prop_iter = (&mut prop_iter)
                    .skip_while(|(_, props)| !top_is_category(props, curr_subcategory))
                    .take_while(|(_, props)| top_is_category(props, curr_subcategory))
                    .map(|((i, c), props)| {
                        props.pop_first();
                        (i, c)
                    });
                if let Some((min, min_c)) = prop_iter.next() {
                    let (max, max_c) = prop_iter.last().unwrap_or((min, min_c));
                    subprop_ranges.push(((min, max + max_c.len_utf8()), curr_subcategory));
                } else {
                    break;
                }
            }
        }

        (prop_ranges, subprop_ranges)
    }
}

impl<S> UsesState for StringCategoriesStage<S>
where
    S: UsesInput,
{
    type State = S;
}

impl<S, E, EM, Z> Stage<E, EM, Z> for StringCategoriesStage<S>
where
    S: UsesInput<Input = BytesInput> + HasCorpus + HasTestcase,
    E: UsesState<State = S>,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
{
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        _manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        let mut testcase = state.testcase_mut(corpus_idx)?;
        if testcase.has_metadata::<StringCategoryMetadata>() {
            return Ok(()); // already classified
        }

        let input = testcase.load_input(state.corpus())?;

        let bytes = input.bytes();
        let metadata = if let Ok(string) = core::str::from_utf8(bytes) {
            let categories = Rc::new(Self::group_by_categories(string));
            StringCategoryMetadata::CategoryRanges { categories }
        } else {
            StringCategoryMetadata::Unclassifiable
        };
        testcase.add_metadata(metadata);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::state::NopState;

    // a not-so-useful test for this
    #[test]
    fn check_hex() {
        let hex = "0123456789abcdef0123456789abcdef";
        let category_ranges =
            StringCategoriesStage::<NopState<BytesInput>>::group_by_categories(hex);

        for (range, prop) in category_ranges.0 {
            let prop = unicode_categories::BY_NAME[prop].0;
            println!(
                "{prop}: {} ({range:?})",
                core::str::from_utf8(&hex.as_bytes()[range.0..range.1]).unwrap()
            );
        }
    }
}
