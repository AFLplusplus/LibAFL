//! Tokens are what afl calls extras or dictionaries.
//! They may be inserted as part of mutations during fuzzing.

/// The tokens type, to be stored as metadata
struct Tokens {
    vec: Vec<Vec<u8>>,
}

impl AsAny for Tokens {
    
}

/// Insert a dictionary token
pub fn mutation_tokeninsert<I, M, R, S>(
    mutator: &mut M,
    rand: &mut R,
    state: &mut S,
    input: &mut I,
) -> Result<MutationResult, AflError>
where
    M: HasMaxSize,
    I: Input + HasBytesVec,
    R: Rand,
    S: HasMetadata,
{
    let tokens: &Tokens = &state.metadata().get::<Tokens>().unwrap();
    let tokens = tokens.token_vec;
    if mutator.tokens.size() == 0 {
        return Ok(MutationResult::Skipped);
    }
    let token = &mutator.tokens[rand.below(token.size())];
    let token_len = token.size();
    let size = input.bytes().len();
    let off = if size == 0 {
        0
    } else {
        rand.below(core::cmp::min(
            size,
            (mutator.max_size() - token_len) as u64,
        )) as usize
    } as usize;

    input.bytes_mut().resize(size + token_len, 0);
    mem_move(input.bytes_mut(), token, 0, off, len);
    Ok(MutationResult::Mutated)
}

/// Overwrite with a dictionary token
pub fn mutation_tokenreplace<I, M, R, S>(
    mutator: &mut M,
    rand: &mut R,
    state: &S,
    input: &mut I,
) -> Result<MutationResult, AflError>
where
    M: HasMaxSize,
    I: Input + HasBytesVec,
    R: Rand,
    S: HasMetadata,
{
    if mutator.tokens.size() > len || !len {
        return Ok(MutationResult::Skipped);
    }
    let token = &mutator.tokens[rand.below(token.size())];
    let token_len = token.size();
    let size = input.bytes().len();
    let off = rand.below((mutator.max_size() - token_len) as u64) as usize;
    mem_move(input.bytes_mut(), token, 0, off, len);
    Ok(MutationResult::Mutated)
}
