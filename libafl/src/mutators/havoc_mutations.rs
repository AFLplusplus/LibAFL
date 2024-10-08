//! [`crate::mutators::Mutator`] collection equivalent to AFL++'s havoc mutations

use libafl_bolts::{
    merge_tuple_list_type,
    tuples::{Map, Merge},
};
use tuple_list::{tuple_list, tuple_list_type};

use crate::{
    corpus::Corpus,
    inputs::MappedInput,
    mutators::{
        mapping::{
            MappedInputFunctionMappingMutator, OptionMappingMutator,
            ToMappedInputFunctionMappingMutatorMapper, ToOptionMappingMutatorMapper,
        },
        mutations::{
            BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator, ByteIncMutator,
            ByteInterestingMutator, ByteNegMutator, ByteRandMutator, BytesCopyMutator,
            BytesDeleteMutator, BytesExpandMutator, BytesInsertCopyMutator, BytesInsertMutator,
            BytesRandInsertMutator, BytesRandSetMutator, BytesSetMutator, BytesSwapMutator,
            CrossoverInsertMutator, CrossoverReplaceMutator, DwordAddMutator,
            DwordInterestingMutator, MappedCrossoverInsertMutator, MappedCrossoverReplaceMutator,
            QwordAddMutator, WordAddMutator, WordInterestingMutator,
        },
        IntoOptionBytes,
    },
    state::HasCorpus,
};

/// Tuple type of the mutations that compose the Havoc mutator without crossover mutations
pub type HavocMutationsNoCrossoverType = tuple_list_type!(
    BitFlipMutator,
    ByteFlipMutator,
    ByteIncMutator,
    ByteDecMutator,
    ByteNegMutator,
    ByteRandMutator,
    ByteAddMutator,
    WordAddMutator,
    DwordAddMutator,
    QwordAddMutator,
    ByteInterestingMutator,
    WordInterestingMutator,
    DwordInterestingMutator,
    BytesDeleteMutator,
    BytesDeleteMutator,
    BytesDeleteMutator,
    BytesDeleteMutator,
    BytesExpandMutator,
    BytesInsertMutator,
    BytesRandInsertMutator,
    BytesSetMutator,
    BytesRandSetMutator,
    BytesCopyMutator,
    BytesInsertCopyMutator,
    BytesSwapMutator,
);

/// Tuple type of the mutations that compose the Havoc mutator's crossover mutations
pub type HavocCrossoverType = tuple_list_type!(CrossoverInsertMutator, CrossoverReplaceMutator);

/// Tuple type of the mutations that compose the Havoc mutator's crossover mutations for mapped input types
pub type MappedHavocCrossoverType<S, O> = tuple_list_type!(
    MappedCrossoverInsertMutator<S, O>,
    MappedCrossoverReplaceMutator<S, O>,
);

/// Tuple type of the mutations that compose the Havoc mutator
pub type HavocMutationsType =
    merge_tuple_list_type!(HavocMutationsNoCrossoverType, HavocCrossoverType);

/// Tuple type of the mutations that compose the Havoc mutator for mapped input types
pub type MappedHavocMutationsType<S, II1, II2> = tuple_list_type!(
    MappedInputFunctionMappingMutator<BitFlipMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<ByteFlipMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<ByteIncMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<ByteDecMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<ByteNegMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<ByteRandMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<ByteAddMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<WordAddMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<DwordAddMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<QwordAddMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<ByteInterestingMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<WordInterestingMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<DwordInterestingMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<BytesDeleteMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<BytesDeleteMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<BytesDeleteMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<BytesDeleteMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<BytesExpandMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<BytesInsertMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<BytesRandInsertMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<BytesSetMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<BytesRandSetMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<BytesCopyMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<BytesInsertCopyMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<BytesSwapMutator, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<MappedCrossoverInsertMutator<S, II2>, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
    MappedInputFunctionMappingMutator<MappedCrossoverReplaceMutator<S, II2>, <<S as HasCorpus>::Corpus as Corpus>::Input, II1>,
);

/// Tuple type of the mutations that compose the Havoc mutator for mapped input types, for optional byte array input parts
pub type OptionMappedHavocMutationsType<S, II1, II2> = tuple_list_type!(
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<BitFlipMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<ByteFlipMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<ByteIncMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<ByteDecMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<ByteNegMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<ByteRandMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<ByteAddMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<WordAddMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<DwordAddMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<QwordAddMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<ByteInterestingMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<WordInterestingMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<DwordInterestingMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<BytesDeleteMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<BytesDeleteMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<BytesDeleteMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<BytesDeleteMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<BytesExpandMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<BytesInsertMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<BytesRandInsertMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<BytesSetMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<BytesRandSetMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<BytesCopyMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<BytesInsertCopyMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<BytesSwapMutator>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<MappedCrossoverInsertMutator<S, II2>>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<MappedCrossoverReplaceMutator<S, II2>>,
        <<S as HasCorpus>::Corpus as Corpus>::Input,
        II1,
    >
);

/// Get the mutations that compose the Havoc mutator (only applied to single inputs)
#[must_use]
pub fn havoc_mutations_no_crossover() -> HavocMutationsNoCrossoverType {
    tuple_list!(
        BitFlipMutator::new(),
        ByteFlipMutator::new(),
        ByteIncMutator::new(),
        ByteDecMutator::new(),
        ByteNegMutator::new(),
        ByteRandMutator::new(),
        ByteAddMutator::new(),
        WordAddMutator::new(),
        DwordAddMutator::new(),
        QwordAddMutator::new(),
        ByteInterestingMutator::new(),
        WordInterestingMutator::new(),
        DwordInterestingMutator::new(),
        BytesDeleteMutator::new(),
        BytesDeleteMutator::new(),
        BytesDeleteMutator::new(),
        BytesDeleteMutator::new(),
        BytesExpandMutator::new(),
        BytesInsertMutator::new(),
        BytesRandInsertMutator::new(),
        BytesSetMutator::new(),
        BytesRandSetMutator::new(),
        BytesCopyMutator::new(),
        BytesInsertCopyMutator::new(),
        BytesSwapMutator::new(),
    )
}

/// Get the mutations that compose the Havoc mutator's crossover strategy
#[must_use]
pub fn havoc_crossover() -> HavocCrossoverType {
    tuple_list!(
        CrossoverInsertMutator::new(),
        CrossoverReplaceMutator::new(),
    )
}

/// Get the mutations that compose the Havoc mutator's crossover strategy with custom corpus extraction logic
pub fn havoc_crossover_with_corpus_mapper<S, O>(
    input_mapper: fn(&<<S as HasCorpus>::Corpus as Corpus>::Input) -> O::Type<'_>,
) -> MappedHavocCrossoverType<S, O>
where
    S: HasCorpus,
    O: IntoOptionBytes,
{
    tuple_list!(
        MappedCrossoverInsertMutator::new(input_mapper),
        MappedCrossoverReplaceMutator::new(input_mapper),
    )
}

/// Get the mutations that compose the Havoc mutator's crossover strategy with custom corpus extraction logic
pub fn havoc_crossover_with_corpus_mapper_optional<S, O>(
    input_mapper: fn(&<<S as HasCorpus>::Corpus as Corpus>::Input) -> O::Type<'_>,
) -> MappedHavocCrossoverType<S, O>
where
    S: HasCorpus,
    O: IntoOptionBytes,
{
    tuple_list!(
        MappedCrossoverInsertMutator::new(input_mapper),
        MappedCrossoverReplaceMutator::new(input_mapper),
    )
}

/// Get the mutations that compose the Havoc mutator
#[must_use]
pub fn havoc_mutations() -> HavocMutationsType {
    havoc_mutations_no_crossover().merge(havoc_crossover())
}

/// Get the mutations that compose the Havoc mutator for mapped input types
///
/// Check the example fuzzer for details on how to use this.
#[must_use]
pub fn mapped_havoc_mutations<S, IO, II1, II2>(
    current_input_mapper: fn(&mut IO) -> II1::Type<'_>,
    input_from_corpus_mapper: fn(&IO) -> II2::Type<'_>,
) -> MappedHavocMutationsType<S, II1, II2>
where
    for<'a> II1: MappedInput + 'a,
    S::Corpus: Corpus<Input = IO>,
    S: HasCorpus,
    II2: IntoOptionBytes,
{
    havoc_mutations_no_crossover()
        .merge(havoc_crossover_with_corpus_mapper(input_from_corpus_mapper))
        .map(ToMappedInputFunctionMappingMutatorMapper::new(
            current_input_mapper,
        ))
}

/// Get the mutations that compose the Havoc mutator for mapped input types, for optional input parts
///
/// Check the example fuzzer for details on how to use this.
#[must_use]
pub fn optional_mapped_havoc_mutations<S, II1, II2>(
    current_input_mapper: fn(&mut <<S as HasCorpus>::Corpus as Corpus>::Input) -> II1::Type<'_>,
    input_from_corpus_mapper: fn(&<<S as HasCorpus>::Corpus as Corpus>::Input) -> II2::Type<'_>,
) -> OptionMappedHavocMutationsType<S, II1, II2>
where
    II1: MappedInput,
    S: HasCorpus,
    II2: IntoOptionBytes,
{
    havoc_mutations_no_crossover()
        .merge(havoc_crossover_with_corpus_mapper_optional(
            input_from_corpus_mapper,
        ))
        .map(ToOptionMappingMutatorMapper)
        .map(ToMappedInputFunctionMappingMutatorMapper::new(
            current_input_mapper,
        ))
}

#[cfg(test)]
mod tests {
    use std::string::{String, ToString};

    use libafl_bolts::rands::StdRand;
    use serde::{Deserialize, Serialize};

    use super::{mapped_havoc_mutations, MappedHavocMutationsType};
    use crate::{
        corpus::{Corpus, CorpusId, InMemoryCorpus},
        inputs::{Input, MutVecInput},
        mutators::{DefaultMutators, MutationResult, StdScheduledMutator, Vec},
        prelude::Mutator as _,
        state::{HasCorpus, StdState},
    };

    #[test]
    fn test_default_mutators_custom_implementation() {
        #[derive(Debug, Deserialize, Serialize, SerdeAny, Clone)]
        struct CustomInput {
            vec: Vec<u8>,
        }

        impl CustomInput {
            fn vec_mut(&mut self) -> MutVecInput<'_> {
                (&mut self.vec).into()
            }
            fn vec(&self) -> &[u8] {
                &self.vec
            }
        }
        impl<S> DefaultMutators<S, MappedHavocMutationsType<S, MutVecInput<'static>, &'static [u8]>>
            for CustomInput
        where
            S: HasCorpus,
        {
            fn default_mutators() -> MappedHavocMutationsType<S, MutVecInput<'static>, &'static [u8]>
            where
                S::Corpus: Corpus<Input = Self>,
            {
                mapped_havoc_mutations(Self::vec_mut, Self::vec)
            }
        }

        impl Input for CustomInput {
            fn generate_name(&self, _id: Option<CorpusId>) -> String {
                "CustomInput".to_string()
            }
        }
        let mut input = CustomInput {
            vec: vec![0x1, 0x2, 0x3],
        };
        let mutations = CustomInput::default_mutators();
        let mut scheduler = StdScheduledMutator::new(mutations);
        let mut corpus = InMemoryCorpus::new();
        corpus.add(input.clone().into()).unwrap();
        let mut state = StdState::new(
            StdRand::new(),
            corpus,
            InMemoryCorpus::new(),
            &mut (),
            &mut (),
        )
        .unwrap();

        let res = scheduler.mutate(&mut state, &mut input).unwrap();
        assert_eq!(res, MutationResult::Mutated);
    }
}
