//! [`crate::mutators::Mutator`] collection equivalent to AFL++'s havoc mutations

use libafl_bolts::tuples::{Map, Merge};
use tuple_list::{tuple_list, tuple_list_type};

use crate::mutators::{
    mapping::{
        FunctionMappingMutator, OptionMappingMutator, ToFunctionMappingMutatorMapper,
        ToOptionMappingMutatorMapper,
    },
    mutations::{
        BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator, ByteIncMutator,
        ByteInterestingMutator, ByteNegMutator, ByteRandMutator, BytesCopyMutator,
        BytesDeleteMutator, BytesExpandMutator, BytesInsertCopyMutator, BytesInsertMutator,
        BytesRandInsertMutator, BytesRandSetMutator, BytesSetMutator, BytesSwapMutator,
        CrossoverInsertMutator, CrossoverReplaceMutator, DwordAddMutator, DwordInterestingMutator,
        MappedCrossoverInsertMutator, MappedCrossoverReplaceMutator, QwordAddMutator,
        WordAddMutator, WordInterestingMutator,
    },
};

/// Tuple type of the mutations that compose the Havoc mutator without crossover mutations
pub type HavocMutationsNoCrossoverType = tuple_list_type!(
    BitFlipMutator,
    /*ByteFlipMutator,
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
    BytesSwapMutator,*/
);

/// Tuple type of the mutations that compose the Havoc mutator's crossover mutations
pub type HavocCrossoverType<I> =
    tuple_list_type!(CrossoverInsertMutator<I>, CrossoverReplaceMutator<I>);

/// Tuple type of the mutations that compose the Havoc mutator's crossover mutations for mapped input types
pub type MappedHavocCrossoverType<'a, F> = tuple_list_type!(
    MappedCrossoverInsertMutator<'a, F>,
    MappedCrossoverReplaceMutator<'a, F>
);

/// Tuple type of the mutations that compose the Havoc mutator
pub type HavocMutationsType = tuple_list_type!(
    BitFlipMutator,
    /*ByteFlipMutator,
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
    CrossoverInsertMutator<I>,
    CrossoverReplaceMutator<I>,*/
);

/// Tuple type of the mutations that compose the Havoc mutator for mapped input types
pub type MappedHavocMutationsType<'a, F1> = tuple_list_type!(
    FunctionMappingMutator<BitFlipMutator, F1>,
    /*FunctionMappingMutator<ByteFlipMutator, F1>,
    FunctionMappingMutator<ByteIncMutator, F1>,
    FunctionMappingMutator<ByteDecMutator, F1>,
    FunctionMappingMutator<ByteNegMutator, F1>,
    FunctionMappingMutator<ByteRandMutator, F1>,
    FunctionMappingMutator<ByteAddMutator, F1>,
    FunctionMappingMutator<WordAddMutator, F1>,
    FunctionMappingMutator<DwordAddMutator, F1>,
    FunctionMappingMutator<QwordAddMutator, F1>,
    FunctionMappingMutator<ByteInterestingMutator, F1>,
    FunctionMappingMutator<WordInterestingMutator, F1>,
    FunctionMappingMutator<DwordInterestingMutator, F1>,
    FunctionMappingMutator<MutVecMappingMutator<BytesDeleteMutator>, F1>,
    FunctionMappingMutator<MutVecMappingMutator<BytesDeleteMutator>, F1>,
    FunctionMappingMutator<MutVecMappingMutator<BytesDeleteMutator>, F1>,
    FunctionMappingMutator<MutVecMappingMutator<BytesDeleteMutator>, F1>,
    FunctionMappingMutator<MutVecMappingMutator<BytesExpandMutator>, F1>,
    FunctionMappingMutator<MutVecMappingMutator<BytesInsertMutator>, F1>,
    FunctionMappingMutator<MutVecMappingMutator<BytesRandInsertMutator>, F1>,
    FunctionMappingMutator<MutVecMappingMutator<BytesSetMutator>, F1>,
    FunctionMappingMutator<MutVecMappingMutator<BytesRandSetMutator>, F1>,
    FunctionMappingMutator<MutVecMappingMutator<BytesCopyMutator>, F1>,
    FunctionMappingMutator<MutVecMappingMutator<BytesInsertCopyMutator>, F1>,
    FunctionMappingMutator<MutVecMappingMutator<BytesSwapMutator>, F1>,
    FunctionMappingMutator<MutVecMappingMutator<MappedCrossoverInsertMutator<'a, F2>>, F1>,
    FunctionMappingMutator<MutVecMappingMutator<MappedCrossoverReplaceMutator<'a, F2>>, F1>,*/
);

/// Tuple type of the mutations that compose the Havoc mutator for mapped input types, for optional byte array input parts
/*pub type OptionMappedHavocMutationsType<'a, F1> = tuple_list_type!(
    FunctionMappingMutator<OptionMappingMutator<BitFlipMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<ByteFlipMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<ByteIncMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<ByteDecMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<ByteNegMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<ByteRandMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<ByteAddMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<WordAddMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<DwordAddMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<QwordAddMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<ByteInterestingMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<WordInterestingMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<DwordInterestingMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<BytesDeleteMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<BytesDeleteMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<BytesDeleteMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<BytesDeleteMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<BytesExpandMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<BytesInsertMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<BytesRandInsertMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<BytesSetMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<BytesRandSetMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<BytesCopyMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<BytesInsertCopyMutator>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MutVecMappingMutator<BytesSwapMutator>>, F1>,
    FunctionMappingMutator<
        OptionMappingMutator<MutVecMappingMutator<MappedCrossoverInsertMutator<'a, F2>>>,
        F1,
    >,
    FunctionMappingMutator<
        OptionMappingMutator<MutVecMappingMutator<MappedCrossoverReplaceMutator<'a, F2>>>,
        F1,
    >,
);*/

/// Get the mutations that compose the Havoc mutator (only applied to single inputs)
#[must_use]
pub fn havoc_mutations_no_crossover() -> HavocMutationsNoCrossoverType {
    tuple_list!(
        BitFlipMutator::new(),
        /*ByteFlipMutator::new(),
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
        BytesSwapMutator::new(),*/
    )
}

/// Get the mutations that compose the Havoc mutator's crossover strategy
#[must_use]
pub fn havoc_crossover<I>() -> HavocCrossoverType<I> {
    tuple_list!(
        CrossoverInsertMutator::new(),
        CrossoverReplaceMutator::new(),
    )
}

/// Get the mutations that compose the Havoc mutator's crossover strategy with custom corpus extraction logic
pub fn havoc_crossover_with_corpus_mapper<F>(corpus_mapper: &F) -> MappedHavocCrossoverType<'_, F> {
    tuple_list!(
        MappedCrossoverInsertMutator::new(corpus_mapper),
        MappedCrossoverReplaceMutator::new(corpus_mapper),
    )
}

// /// Get the mutations that compose the Havoc mutator
// #[must_use]
// pub fn havoc_mutations<I>() -> HavocMutationsType<I> {
//     havoc_mutations_no_crossover().merge(havoc_crossover())
// }

/// Get the mutations that compose the Havoc mutator for mapped input types
#[must_use]
pub fn mapped_havoc_mutations<'a, F1>(
    current_input_mapper: F1,
    //input_from_corpus_mapper: &F2,
) -> MappedHavocMutationsType<'a, F1>
where
    F1: Clone,
{
    havoc_mutations_no_crossover()
        //.merge(havoc_crossover_with_corpus_mapper(input_from_corpus_mapper))
        //.map(ToMutVecMappingMutatorMapper)
        .map(ToFunctionMappingMutatorMapper::new(current_input_mapper))
}

// /// Get the mutations that compose the Havoc mutator for mapped input types, for optional byte array input parts
// #[must_use]
// pub fn optional_mapped_havoc_mutations<F1, F2>(
//     current_input_mapper: F1,
//     input_from_corpus_mapper: &F2,
// ) -> OptionMappedHavocMutationsType<'_, F1, F2>
// where
//     F1: Clone,
// {
//     havoc_mutations_no_crossover()
//         .merge(havoc_crossover_with_corpus_mapper(input_from_corpus_mapper))
//         .map(ToMutVecMappingMutatorMapper)
//         .map(ToOptionMappingMutatorMapper)
//         .map(ToFunctionMappingMutatorMapper::new(current_input_mapper))
// }
