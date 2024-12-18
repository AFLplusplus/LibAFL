//! [`crate::mutators::Mutator`] collection equivalent to AFL++'s havoc mutations

use libafl_bolts::tuples::{Map, Merge};
use tuple_list::{tuple_list, tuple_list_type};

use super::{FunctionMappingMutator, ToFunctionMappingMutatorMapper};
use crate::mutators::{
    mapping::{OptionMappingMutator, ToOptionMappingMutatorMapper},
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
    FunctionMappingMutator<BitFlipMutator, F1>,
    FunctionMappingMutator<ByteFlipMutator, F1>,
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
    FunctionMappingMutator<BytesDeleteMutator, F1>,
    FunctionMappingMutator<BytesDeleteMutator, F1>,
    FunctionMappingMutator<BytesDeleteMutator, F1>,
    FunctionMappingMutator<BytesDeleteMutator, F1>,
    FunctionMappingMutator<BytesExpandMutator, F1>,
    FunctionMappingMutator<BytesInsertMutator, F1>,
    FunctionMappingMutator<BytesRandInsertMutator, F1>,
    FunctionMappingMutator<BytesSetMutator, F1>,
    FunctionMappingMutator<BytesRandSetMutator, F1>,
    FunctionMappingMutator<BytesCopyMutator, F1>,
    FunctionMappingMutator<BytesInsertCopyMutator, F1>,
    FunctionMappingMutator<BytesSwapMutator, F1>,
    FunctionMappingMutator<MappedCrossoverInsertMutator<F2, O>, F1>,
    FunctionMappingMutator<MappedCrossoverReplaceMutator<F2, O>, F1>,
);

/// Tuple type of the mutations that compose the Havoc mutator for mapped input types, for optional byte array input parts
pub type OptionMappedHavocMutationsType<F1, F2, O> = tuple_list_type!(
    FunctionMappingMutator<OptionMappingMutator<BitFlipMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<ByteFlipMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<ByteIncMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<ByteDecMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<ByteNegMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<ByteRandMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<ByteAddMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<WordAddMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<DwordAddMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<QwordAddMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<ByteInterestingMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<WordInterestingMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<DwordInterestingMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<BytesDeleteMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<BytesDeleteMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<BytesDeleteMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<BytesDeleteMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<BytesExpandMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<BytesInsertMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<BytesRandInsertMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<BytesSetMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<BytesRandSetMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<BytesCopyMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<BytesInsertCopyMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<BytesSwapMutator>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MappedCrossoverInsertMutator<F2, O>>, F1>,
    FunctionMappingMutator<OptionMappingMutator<MappedCrossoverReplaceMutator<F2, O>>, F1>,
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
        .map(ToFunctionMappingMutatorMapper::new(current_input_mapper))
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
        .map(ToOptionMappingMutatorMapper)
        .map(ToFunctionMappingMutatorMapper::new(current_input_mapper))
}
