//! [`Mutator`] collection equivalent to AFL++'s havoc mutations

use crate::mutators::{
    mapping::{
        FunctionMappingMutator, MutVecMappingMutator, ToFunctionMappingMutatorMapper,
        ToMutVecMappingMutatorMapper,
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

use alloc::vec::Vec;
use libafl_bolts::tuples::{Map, Merge};
use tuple_list::{tuple_list, tuple_list_type};

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

/// Tuple type of the mutations that compose the Havoc mutator without crossover mutations for mapped input types
pub type MappedHavocMutationsNoCrossoverType<I> = tuple_list_type!(
    FunctionMappingMutator<MutVecMappingMutator<BitFlipMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<ByteFlipMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<ByteIncMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<ByteDecMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<ByteNegMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<ByteRandMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<ByteAddMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<WordAddMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<DwordAddMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<QwordAddMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<ByteInterestingMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<WordInterestingMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<DwordInterestingMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesDeleteMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesDeleteMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesDeleteMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesDeleteMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesExpandMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesInsertMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesRandInsertMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesSetMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesRandSetMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesCopyMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesInsertCopyMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesSwapMutator>, I, Vec<u8>>,
);

/// Tuple type of the mutations that compose the Havoc mutator without crossover mutations for mapped optional input types
// pub type OptionMappedHavocMutationsNoCrossoverType<I> = tuple_list_type!(
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<BitFlipMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<ByteFlipMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<ByteIncMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<ByteDecMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<ByteNegMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<ByteRandMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<ByteAddMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<WordAddMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<DwordAddMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<QwordAddMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<ByteInterestingMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<WordInterestingMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<DwordInterestingMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<BytesDeleteMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<BytesDeleteMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<BytesDeleteMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<BytesDeleteMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<BytesExpandMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<BytesInsertMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<BytesRandInsertMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<BytesSetMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<BytesRandSetMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<BytesCopyMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<BytesInsertCopyMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
//     FunctionMappingMutator<
//         OptionMappingMutator<MutVecMappingMutator<BytesSwapMutator>>,
//         I,
//         Option<&mut Vec<u8>>,
//     >,
// );

/// Tuple type of the mutations that compose the Havoc mutator's crossover mutations
pub type HavocCrossoverType<I> =
    tuple_list_type!(CrossoverInsertMutator<I>, CrossoverReplaceMutator<I>);

/// Tuple type of the mutations that compose the Havoc mutator's crossover mutations for mapped input types
pub type MappedHavocCrossoverType<I> = tuple_list_type!(
    MappedCrossoverInsertMutator<I>,
    MappedCrossoverReplaceMutator<I>
);

/// Tuple type of the mutations that compose the Havoc mutator
pub type HavocMutationsType<I> = tuple_list_type!(
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
    CrossoverInsertMutator<I>,
    CrossoverReplaceMutator<I>,
);

/// Tuple type of the mutations that compose the Havoc mutator for mapped input types
pub type MappedHavocMutationsType<I> = tuple_list_type!(
    FunctionMappingMutator<MutVecMappingMutator<BitFlipMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<ByteFlipMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<ByteIncMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<ByteDecMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<ByteNegMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<ByteRandMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<ByteAddMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<WordAddMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<DwordAddMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<QwordAddMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<ByteInterestingMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<WordInterestingMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<DwordInterestingMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesDeleteMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesDeleteMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesDeleteMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesDeleteMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesExpandMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesInsertMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesRandInsertMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesSetMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesRandSetMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesCopyMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesInsertCopyMutator>, I, Vec<u8>>,
    FunctionMappingMutator<MutVecMappingMutator<BytesSwapMutator>, I, Vec<u8>>,
    MappedCrossoverInsertMutator<I>,
    MappedCrossoverReplaceMutator<I>,
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

/// Get the mutations that compose the Havoc mutator (only applied to single inputs) for mapped input types
#[must_use]
pub fn mapped_havoc_mutations_no_crossover<I>(
    mapper: for<'b> fn(&'b mut I) -> &'b mut Vec<u8>,
) -> MappedHavocMutationsNoCrossoverType<I> {
    havoc_mutations_no_crossover()
        .map(ToMutVecMappingMutatorMapper)
        .map(ToFunctionMappingMutatorMapper::new(mapper))
}

/// Get the mutations that compose the Havoc mutator's crossover strategy
#[must_use]
pub fn havoc_crossover<I>() -> HavocCrossoverType<I> {
    tuple_list!(
        CrossoverInsertMutator::new(),
        CrossoverReplaceMutator::new(),
    )
}

/// Get the mutations that compose the Havoc mutator's crossover strategy for mapped input types
#[must_use]
pub fn mapped_havoc_crossover<I>(
    mapper: for<'b> fn(&'b I) -> &'b Vec<u8>,
    mapper_mut: for<'b> fn(&'b mut I) -> &'b mut Vec<u8>,
) -> MappedHavocCrossoverType<I> {
    tuple_list!(
        MappedCrossoverInsertMutator::new(mapper, mapper_mut),
        MappedCrossoverReplaceMutator::new(mapper, mapper_mut),
    )
}

/// Get the mutations that compose the Havoc mutator
#[must_use]
pub fn havoc_mutations<I>() -> HavocMutationsType<I> {
    havoc_mutations_no_crossover().merge(havoc_crossover())
}

/// Get the mutations that compose the Havoc mutator for mapped input types
#[must_use]
pub fn mapped_havoc_mutations<I>(
    mapper: for<'b> fn(&'b I) -> &'b Vec<u8>,
    mapper_mut: for<'b> fn(&'b mut I) -> &'b mut Vec<u8>,
) -> MappedHavocMutationsType<I> {
    mapped_havoc_mutations_no_crossover(mapper_mut)
        .merge(mapped_havoc_crossover(mapper, mapper_mut))
}
