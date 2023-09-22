use alloc::{borrow::Cow, collections::BTreeSet, vec::Vec};
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

mod unicode_properties {
    include!(concat!(env!("OUT_DIR"), "/unicode_properties.rs"));
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum StringClassificationMetadata {
    Unclassifiable,
    Classifications(Vec<BTreeSet<Cow<'static, str>>>),
}

impl_serdeany!(StringClassificationMetadata);

pub struct StringClassificationStage<S> {
    phantom: PhantomData<S>,
}

impl<S> UsesState for StringClassificationStage<S>
where
    S: UsesInput,
{
    type State = S;
}

impl<S, E, EM, Z> Stage<E, EM, Z> for StringClassificationStage<S>
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
        if testcase.has_metadata::<StringClassificationMetadata>() {
            return Ok(()); // already classified
        }

        let input = testcase.load_input(state.corpus())?;
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        let bytes = input.bytes();
        let metadata = if let Ok(string) = core::str::from_utf8(bytes) {
            let mut char_properties = vec![BTreeSet::new(); string.chars().count()];
            for &(name, ranges) in unicode_properties::BY_NAME {
                let ranges: &'static [(u32, u32)] = ranges; // type inference help for IDEs
                let min = ranges.first().unwrap().0;
                let max = ranges.last().unwrap().1;

                for (c, properties) in string.chars().zip(char_properties.iter_mut()) {
                    let value = c as u32;
                    if min <= value && value <= max {
                        if ranges
                            .binary_search_by(|&(min, max)| match min.cmp(&value) {
                                Ordering::Less | Ordering::Equal => match value.cmp(&max) {
                                    Ordering::Less | Ordering::Equal => Ordering::Equal,
                                    Ordering::Greater => Ordering::Less,
                                },
                                Ordering::Greater => Ordering::Greater,
                            })
                            .is_ok()
                        {
                            properties.insert(Cow::from(name));
                        }
                    }
                }
            }
            StringClassificationMetadata::Classifications(char_properties)
        } else {
            StringClassificationMetadata::Unclassifiable
        };
        testcase.add_metadata(metadata);
        Ok(())
    }
}
