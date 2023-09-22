use alloc::{collections::BTreeSet, vec::Vec};
use core::{cmp::Ordering, marker::PhantomData};

use libafl_bolts::{impl_serdeany, Error};
use serde::{Deserialize, Serialize};

use crate::{
    corpus::{CorpusId, HasTestcase},
    inputs::{BytesInput, HasBytesVec, UsesInput},
    mark_feature_time,
    stages::Stage,
    start_timer,
    state::{HasCorpus, HasMetadata, UsesState},
};

pub mod unicode_properties {
    include!(concat!(env!("OUT_DIR"), "/unicode_properties.rs"));
}

pub type PropertyRange = ((usize, usize), usize);
pub type PropertyRanges = Vec<PropertyRange>;
pub type SubpropertyRange = ((usize, usize), (u32, u32));
pub type SubpropertyRanges = Vec<SubpropertyRange>;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum StringPropertiesMetadata {
    Unclassifiable,
    PropertyRanges {
        properties: PropertyRanges,
        subproperties: SubpropertyRanges,
    },
}

impl_serdeany!(StringPropertiesMetadata);

#[derive(Debug)]
pub struct StringPropertiesStage<S> {
    phantom: PhantomData<S>,
}

impl<S> StringPropertiesStage<S> {
    pub(crate) fn group_by_properties(string: &str) -> (PropertyRanges, SubpropertyRanges) {
        let mut char_properties = vec![BTreeSet::new(); string.chars().count()];
        let mut all_properties = BTreeSet::new();

        let mut char_subproperties = vec![BTreeSet::new(); char_properties.len()];
        let mut all_subproperties = BTreeSet::new();
        for (prop, &(_, ranges)) in unicode_properties::BY_NAME.iter().enumerate() {
            // type inference help for IDEs
            let prop: usize = prop;
            let ranges: &'static [(u32, u32)] = ranges;

            let min = ranges.first().unwrap().0;
            let max = ranges.last().unwrap().1;

            for (c, (properties, subproperties)) in string.chars().zip(
                char_properties
                    .iter_mut()
                    .zip(char_subproperties.iter_mut()),
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
                        properties.insert(prop);
                        all_properties.insert(prop);
                        subproperties.insert(ranges[subprop]);
                        all_subproperties.insert(ranges[subprop]);
                    }
                }
            }
        }

        fn top_is_property<T: Copy + Eq + Ord>(props: &BTreeSet<T>, prop: T) -> bool {
            props.first().map_or(false, |&i| i == prop)
        }

        let mut prop_ranges = Vec::new();
        for curr_property in all_properties {
            let mut prop_iter = string.char_indices().zip(char_properties.iter_mut());
            loop {
                let mut prop_iter = (&mut prop_iter)
                    .skip_while(|(_, props)| !top_is_property(props, curr_property))
                    .take_while(|(_, props)| top_is_property(props, curr_property))
                    .map(|((i, c), props)| {
                        props.pop_first();
                        (i, c)
                    });
                if let Some((min, min_c)) = prop_iter.next() {
                    let (max, max_c) = prop_iter.last().unwrap_or((min, min_c));
                    prop_ranges.push(((min, max + max_c.len_utf8()), curr_property));
                } else {
                    break;
                }
            }
        }

        let mut subprop_ranges = Vec::new();
        for curr_subproperty in all_subproperties {
            let mut prop_iter = string.char_indices().zip(char_subproperties.iter_mut());
            loop {
                let mut prop_iter = (&mut prop_iter)
                    .skip_while(|(_, props)| !top_is_property(props, curr_subproperty))
                    .take_while(|(_, props)| top_is_property(props, curr_subproperty))
                    .map(|((i, c), props)| {
                        props.pop_first();
                        (i, c)
                    });
                if let Some((min, min_c)) = prop_iter.next() {
                    let (max, max_c) = prop_iter.last().unwrap_or((min, min_c));
                    subprop_ranges.push(((min, max + max_c.len_utf8()), curr_subproperty));
                } else {
                    break;
                }
            }
        }

        (prop_ranges, subprop_ranges)
    }
}

impl<S> UsesState for StringPropertiesStage<S>
where
    S: UsesInput,
{
    type State = S;
}

impl<S, E, EM, Z> Stage<E, EM, Z> for StringPropertiesStage<S>
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
        start_timer!(state);
        let mut testcase = state.testcase_mut(corpus_idx)?;
        if testcase.has_metadata::<StringPropertiesMetadata>() {
            return Ok(()); // already classified
        }

        let input = testcase.load_input(state.corpus())?;
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        let bytes = input.bytes();
        let metadata = if let Ok(string) = core::str::from_utf8(bytes) {
            let (properties, subproperties) = Self::group_by_properties(string);
            StringPropertiesMetadata::PropertyRanges {
                properties,
                subproperties,
            }
        } else {
            StringPropertiesMetadata::Unclassifiable
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
        let property_ranges =
            StringPropertiesStage::<NopState<BytesInput>>::group_by_properties(hex);

        for (range, prop) in property_ranges.0 {
            let prop = unicode_properties::BY_NAME[prop].0;
            println!(
                "{prop}: {} ({range:?})",
                core::str::from_utf8(&hex.as_bytes()[range.0..range.1]).unwrap()
            );
        }
    }
}
