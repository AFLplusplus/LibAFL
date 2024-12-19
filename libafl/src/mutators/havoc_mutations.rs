//! [`crate::mutators::Mutator`] collection equivalent to AFL++'s havoc mutations

use libafl_bolts::tuples::{Map, Merge};
use tuple_list::{tuple_list, tuple_list_type};

use super::{MappingMutator, ToMappingMutator};
use crate::mutators::{
    mapping::{OptionalMutator, ToOptionalMutator},
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
pub type MappedHavocMutationsType<F1, F2, O> = tuple_list_type!(
    MappingMutator<BitFlipMutator, F1>,
    MappingMutator<ByteFlipMutator, F1>,
    MappingMutator<ByteIncMutator, F1>,
    MappingMutator<ByteDecMutator, F1>,
    MappingMutator<ByteNegMutator, F1>,
    MappingMutator<ByteRandMutator, F1>,
    MappingMutator<ByteAddMutator, F1>,
    MappingMutator<WordAddMutator, F1>,
    MappingMutator<DwordAddMutator, F1>,
    MappingMutator<QwordAddMutator, F1>,
    MappingMutator<ByteInterestingMutator, F1>,
    MappingMutator<WordInterestingMutator, F1>,
    MappingMutator<DwordInterestingMutator, F1>,
    MappingMutator<BytesDeleteMutator, F1>,
    MappingMutator<BytesDeleteMutator, F1>,
    MappingMutator<BytesDeleteMutator, F1>,
    MappingMutator<BytesDeleteMutator, F1>,
    MappingMutator<BytesExpandMutator, F1>,
    MappingMutator<BytesInsertMutator, F1>,
    MappingMutator<BytesRandInsertMutator, F1>,
    MappingMutator<BytesSetMutator, F1>,
    MappingMutator<BytesRandSetMutator, F1>,
    MappingMutator<BytesCopyMutator, F1>,
    MappingMutator<BytesInsertCopyMutator, F1>,
    MappingMutator<BytesSwapMutator, F1>,
    MappingMutator<MappedCrossoverInsertMutator<F2, O>, F1>,
    MappingMutator<MappedCrossoverReplaceMutator<F2, O>, F1>,
);

/// Tuple type of the mutations that compose the Havoc mutator for mapped input types, for optional byte array input parts
pub type OptionMappedHavocMutationsType<F1, F2, O> = tuple_list_type!(
    MappingMutator<OptionalMutator<BitFlipMutator>, F1>,
    MappingMutator<OptionalMutator<ByteFlipMutator>, F1>,
    MappingMutator<OptionalMutator<ByteIncMutator>, F1>,
    MappingMutator<OptionalMutator<ByteDecMutator>, F1>,
    MappingMutator<OptionalMutator<ByteNegMutator>, F1>,
    MappingMutator<OptionalMutator<ByteRandMutator>, F1>,
    MappingMutator<OptionalMutator<ByteAddMutator>, F1>,
    MappingMutator<OptionalMutator<WordAddMutator>, F1>,
    MappingMutator<OptionalMutator<DwordAddMutator>, F1>,
    MappingMutator<OptionalMutator<QwordAddMutator>, F1>,
    MappingMutator<OptionalMutator<ByteInterestingMutator>, F1>,
    MappingMutator<OptionalMutator<WordInterestingMutator>, F1>,
    MappingMutator<OptionalMutator<DwordInterestingMutator>, F1>,
    MappingMutator<OptionalMutator<BytesDeleteMutator>, F1>,
    MappingMutator<OptionalMutator<BytesDeleteMutator>, F1>,
    MappingMutator<OptionalMutator<BytesDeleteMutator>, F1>,
    MappingMutator<OptionalMutator<BytesDeleteMutator>, F1>,
    MappingMutator<OptionalMutator<BytesExpandMutator>, F1>,
    MappingMutator<OptionalMutator<BytesInsertMutator>, F1>,
    MappingMutator<OptionalMutator<BytesRandInsertMutator>, F1>,
    MappingMutator<OptionalMutator<BytesSetMutator>, F1>,
    MappingMutator<OptionalMutator<BytesRandSetMutator>, F1>,
    MappingMutator<OptionalMutator<BytesCopyMutator>, F1>,
    MappingMutator<OptionalMutator<BytesInsertCopyMutator>, F1>,
    MappingMutator<OptionalMutator<BytesSwapMutator>, F1>,
    MappingMutator<OptionalMutator<MappedCrossoverInsertMutator<F2, O>>, F1>,
    MappingMutator<OptionalMutator<MappedCrossoverReplaceMutator<F2, O>>, F1>,
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
    F: Clone + Fn(&IO) -> &O,
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
) -> MappedHavocMutationsType<F1, F2, O>
where
    F1: Clone + FnMut(&mut IO1) -> &mut II,
    F2: Clone + Fn(&IO2) -> &O,
{
    havoc_mutations_no_crossover()
        .merge(havoc_crossover_with_corpus_mapper(input_from_corpus_mapper))
        .map(ToMappingMutator::new(current_input_mapper))
}

/// Get the mutations that compose the Havoc mutator for mapped input types, for optional input parts
///
/// Check the example fuzzer for details on how to use this.
#[must_use]
pub fn optional_mapped_havoc_mutations<F1, F2, IO1, IO2, II, O>(
    current_input_mapper: F1,
    input_from_corpus_mapper: F2,
) -> OptionMappedHavocMutationsType<F1, F2, O>
where
    F1: Clone + FnMut(&mut IO1) -> &mut II,
    F2: Clone + Fn(&IO2) -> &O,
{
    havoc_mutations_no_crossover()
        .merge(havoc_crossover_with_corpus_mapper_optional(
            input_from_corpus_mapper,
        ))
        .map(ToOptionalMutator)
        .map(ToMappingMutator::new(current_input_mapper))
}
