//! [`crate::mutators::Mutator`] collection equivalent to AFL++'s havoc mutations

use libafl_bolts::tuples::{Map, Merge};
use tuple_list::{tuple_list, tuple_list_type};

use crate::mutators::{
    mapping::{
        MappedInputFunctionMappingMutator, OptionMappingMutator,
        ToMappedInputFunctionMappingMutatorMapper, ToOptionMappingMutatorMapper,
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
pub type MappedHavocCrossoverType<F, O> = tuple_list_type!(
    MappedCrossoverInsertMutator<F, O>,
    MappedCrossoverReplaceMutator<F, O>,
);

/// Tuple type of the mutations that compose the Havoc mutator
pub type HavocMutationsType = tuple_list_type!(
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
    CrossoverInsertMutator,
    CrossoverReplaceMutator,
);

/// Tuple type of the mutations that compose the Havoc mutator for mapped input types
pub type MappedHavocMutationsType<F1, F2, II, O> = tuple_list_type!(
    MappedInputFunctionMappingMutator<BitFlipMutator, F1, II>,
    MappedInputFunctionMappingMutator<ByteFlipMutator, F1, II>,
    MappedInputFunctionMappingMutator<ByteIncMutator, F1, II>,
    MappedInputFunctionMappingMutator<ByteDecMutator, F1, II>,
    MappedInputFunctionMappingMutator<ByteNegMutator, F1, II>,
    MappedInputFunctionMappingMutator<ByteRandMutator, F1, II>,
    MappedInputFunctionMappingMutator<ByteAddMutator, F1, II>,
    MappedInputFunctionMappingMutator<WordAddMutator, F1, II>,
    MappedInputFunctionMappingMutator<DwordAddMutator, F1, II>,
    MappedInputFunctionMappingMutator<QwordAddMutator, F1, II>,
    MappedInputFunctionMappingMutator<ByteInterestingMutator, F1, II>,
    MappedInputFunctionMappingMutator<WordInterestingMutator, F1, II>,
    MappedInputFunctionMappingMutator<DwordInterestingMutator, F1, II>,
    MappedInputFunctionMappingMutator<BytesDeleteMutator, F1, II>,
    MappedInputFunctionMappingMutator<BytesDeleteMutator, F1, II>,
    MappedInputFunctionMappingMutator<BytesDeleteMutator, F1, II>,
    MappedInputFunctionMappingMutator<BytesDeleteMutator, F1, II>,
    MappedInputFunctionMappingMutator<BytesExpandMutator, F1, II>,
    MappedInputFunctionMappingMutator<BytesInsertMutator, F1, II>,
    MappedInputFunctionMappingMutator<BytesRandInsertMutator, F1, II>,
    MappedInputFunctionMappingMutator<BytesSetMutator, F1, II>,
    MappedInputFunctionMappingMutator<BytesRandSetMutator, F1, II>,
    MappedInputFunctionMappingMutator<BytesCopyMutator, F1, II>,
    MappedInputFunctionMappingMutator<BytesInsertCopyMutator, F1, II>,
    MappedInputFunctionMappingMutator<BytesSwapMutator, F1, II>,
    MappedInputFunctionMappingMutator<MappedCrossoverInsertMutator<F2, O>, F1, II>,
    MappedInputFunctionMappingMutator<MappedCrossoverReplaceMutator<F2, O>, F1, II>,
);

/// Tuple type of the mutations that compose the Havoc mutator for mapped input types, for optional byte array input parts
pub type OptionMappedHavocMutationsType<F1, F2, II, O> = tuple_list_type!(
    MappedInputFunctionMappingMutator<OptionMappingMutator<BitFlipMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<ByteFlipMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<ByteIncMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<ByteDecMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<ByteNegMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<ByteRandMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<ByteAddMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<WordAddMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<DwordAddMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<QwordAddMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<ByteInterestingMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<WordInterestingMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<DwordInterestingMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<BytesDeleteMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<BytesDeleteMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<BytesDeleteMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<BytesDeleteMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<BytesExpandMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<BytesInsertMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<BytesRandInsertMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<BytesSetMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<BytesRandSetMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<BytesCopyMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<BytesInsertCopyMutator>, F1, II>,
    MappedInputFunctionMappingMutator<OptionMappingMutator<BytesSwapMutator>, F1, II>,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<MappedCrossoverInsertMutator<F2, O>>,
        F1,
        II,
    >,
    MappedInputFunctionMappingMutator<
        OptionMappingMutator<MappedCrossoverReplaceMutator<F2, O>>,
        F1,
        II,
    >,
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
pub fn havoc_crossover_with_corpus_mapper<F, IO, O>(
    input_mapper: F,
) -> MappedHavocCrossoverType<F, O>
where
    F: Clone + Fn(IO) -> O,
{
    tuple_list!(
        MappedCrossoverInsertMutator::new(input_mapper.clone()),
        MappedCrossoverReplaceMutator::new(input_mapper.clone()),
    )
}

/// Get the mutations that compose the Havoc mutator's crossover strategy with custom corpus extraction logic
pub fn havoc_crossover_with_corpus_mapper_optional<F, O>(
    input_mapper: F,
) -> MappedHavocCrossoverType<F, O>
where
    F: Clone,
{
    tuple_list!(
        MappedCrossoverInsertMutator::new(input_mapper.clone()),
        MappedCrossoverReplaceMutator::new(input_mapper.clone()),
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
pub fn mapped_havoc_mutations<F1, F2, IO1, IO2, II, O>(
    current_input_mapper: F1,
    input_from_corpus_mapper: F2,
) -> MappedHavocMutationsType<F1, F2, II, O>
where
    F1: Clone + FnMut(IO1) -> II,
    F2: Clone + Fn(IO2) -> O,
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
pub fn optional_mapped_havoc_mutations<F1, F2, IO1, IO2, II, O>(
    current_input_mapper: F1,
    input_from_corpus_mapper: F2,
) -> OptionMappedHavocMutationsType<F1, F2, II, O>
where
    F1: Clone + FnMut(IO1) -> II,
    F2: Clone + Fn(IO2) -> O,
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
