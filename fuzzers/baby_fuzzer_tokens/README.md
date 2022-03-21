# Baby tokens fuzzer
1. `tokenizer` are used to split inputs into tokens 
2. `encoder_decoder` will give every new token a new id and record the mapping relation. Then it can convert tokens to `EncodedInput`, vice versa.
3. `encoded_mutations` are used to deal with token level mutation, following is the definition:
'''
pub fn encoded_mutations() -> tuple_list_type!(
    EncodedRandMutator,
    EncodedIncMutator,
    EncodedDecMutator,
    EncodedAddMutator,
    EncodedDeleteMutator,
    EncodedInsertCopyMutator,
    EncodedCopyMutator,
    EncodedCrossoverInsertMutator,
    EncodedCrossoverReplaceMutator,
)
'''