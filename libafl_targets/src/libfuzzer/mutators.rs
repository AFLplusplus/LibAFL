use alloc::{
    borrow::Cow,
    rc::{Rc, Weak},
};
use std::{
    cell::RefCell,
    marker::PhantomData,
    ops::Deref,
    prelude::rust_2015::{Box, Vec},
};

use libafl::{
    corpus::Corpus,
    inputs::{BytesInput, HasMutatorBytes, HasMutatorResizableBytes},
    mutators::{
        ComposedByMutations, MutationId, MutationResult, Mutator, MutatorsTuple, ScheduledMutator,
    },
    random_corpus_id_with_disabled,
    state::{HasCorpus, HasMaxSize, HasRand},
    Error,
};
use libafl_bolts::{rands::Rand, AsSlice, HasLen, Named};

extern "C" {
    fn libafl_targets_has_libfuzzer_custom_mutator() -> bool;
    fn libafl_targets_libfuzzer_custom_mutator(
        data: *mut u8,
        size: usize,
        max_size: usize,
        seed: u32,
    ) -> usize;

    fn libafl_targets_has_libfuzzer_custom_crossover() -> bool;
    fn libafl_targets_libfuzzer_custom_crossover(
        data1: *const u8,
        size1: usize,
        data2: *const u8,
        size2: usize,
        out: *mut u8,
        max_out_size: usize,
        seed: u32,
    ) -> usize;
}

/// Detect the presence of a user-defined custom mutator
#[must_use]
pub fn has_custom_mutator() -> bool {
    unsafe { libafl_targets_has_libfuzzer_custom_mutator() }
}

/// Detect the presence of a user-defined custom crossover
#[must_use]
pub fn has_custom_crossover() -> bool {
    unsafe { libafl_targets_has_libfuzzer_custom_crossover() }
}

/// Erased mutator for dynamic mutator access by the custom mutator/crossover
trait ErasedLLVMFuzzerMutator {
    /// Perform mutation on the desired buffer
    fn mutate(&self, data: *mut u8, size: usize, max_size: usize) -> usize;
}

thread_local! {
    /// The globally accessible mutator reference, if available
    static MUTATOR: RefCell<Option<Box<dyn ErasedLLVMFuzzerMutator>>> = RefCell::new(None);
}

/// Mutator which is available for user-defined mutator/crossover
/// See: [Structure-Aware Fuzzing with libFuzzer](https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md)
#[allow(non_snake_case)] // expect breaks here for some reason
#[no_mangle]
pub extern "C" fn LLVMFuzzerMutate(data: *mut u8, size: usize, max_size: usize) -> usize {
    MUTATOR.with(|mutator| {
        if let Ok(mut mutator) = mutator.try_borrow_mut() {
            if let Some(mutator) = &mut *mutator {
                return mutator.mutate(data, size, max_size);
            }
        }
        unreachable!("Couldn't get mutator!");
    })
}

/// A proxy which wraps a targeted mutator. This is used to provide dynamic access to a global
/// mutator without knowing the concrete type, which is necessary for custom mutators.
struct MutatorProxy<'a, M, S> {
    /// Pointer to the state of the fuzzer
    state: Rc<RefCell<*mut S>>, // refcell to prevent double-mutability over the pointer
    /// A weak reference to the mutator to provide to the custom mutator
    mutator: Weak<RefCell<M>>,
    /// The result of mutation, to be propagated to the mutational stage
    result: Rc<RefCell<Result<MutationResult, Error>>>,
    /// Stage index, which is used by libafl mutator implementations
    phantom: PhantomData<&'a mut ()>,
}

impl<'a, M, S> MutatorProxy<'a, M, S> {
    /// Crate a new mutator proxy for the given state and mutator
    fn new(
        state: &'a mut S,
        mutator: &Rc<RefCell<M>>,
        result: &Rc<RefCell<Result<MutationResult, Error>>>,
    ) -> Self {
        Self {
            state: Rc::new(RefCell::new(state)),
            mutator: Rc::downgrade(mutator),
            result: result.clone(),
            phantom: PhantomData,
        }
    }

    /// Create a weak version of the proxy, which will become unusable when the custom mutator
    /// is no longer permitted to be executed.
    #[allow(clippy::type_complexity)] // no longer a problem in nightly
    fn weak(&self) -> WeakMutatorProxy<impl Fn(&mut dyn for<'b> FnMut(&'b mut S)) -> bool, M, S> {
        let state = Rc::downgrade(&self.state);
        WeakMutatorProxy {
            accessor: move |f: &mut dyn for<'b> FnMut(&'b mut S)| {
                if let Some(state) = state.upgrade() {
                    if let Ok(state) = state.try_borrow_mut() {
                        let state_ref = unsafe { state.as_mut().unwrap_unchecked() };
                        f(state_ref);
                        return true;
                    }
                }
                false
            },
            mutator: self.mutator.clone(),
            result: self.result.clone(),
            phantom: PhantomData,
        }
    }
}

/// A weak proxy to the mutators. In order to preserve Rust memory model semantics, we must ensure
/// that once a libafl mutator exits scope (e.g., once the mutational stage is over) that the
/// mutator is no longer accessible by the custom mutator.
#[derive(Clone)]
struct WeakMutatorProxy<F, M, S> {
    /// Function which will perform the access to the state.
    accessor: F,

    /// A weak reference to the mutator
    mutator: Weak<RefCell<M>>,

    /// The result of mutation, to be propagated to the mutational stage
    result: Rc<RefCell<Result<MutationResult, Error>>>,
    phantom: PhantomData<S>,
}

impl<F, M, S> ErasedLLVMFuzzerMutator for WeakMutatorProxy<F, M, S>
where
    F: Fn(&mut dyn for<'b> FnMut(&'b mut S)) -> bool,
    M: ScheduledMutator<BytesInput, S>,
    M::Mutations: MutatorsTuple<BytesInput, S>,
    S: HasMaxSize,
{
    fn mutate(&self, data: *mut u8, size: usize, max_size: usize) -> usize {
        let mut new_size = 0; // if access fails, the new len is zero
        (self.accessor)(&mut |state| {
            if let Some(mutator) = self.mutator.upgrade() {
                if let Ok(mut mutator) = mutator.try_borrow_mut() {
                    let mut intermediary =
                        BytesInput::from(unsafe { core::slice::from_raw_parts(data, size) });
                    let old = state.max_size();
                    state.set_max_size(max_size);
                    let res = mutator.scheduled_mutate(state, &mut intermediary);
                    state.set_max_size(old);
                    let succeeded = res.is_ok();

                    let mut result = self.result.deref().borrow_mut();
                    *result = res;
                    drop(result);

                    if succeeded {
                        let target = intermediary.bytes();
                        if target.as_slice().len() > max_size {
                            self.result
                                .replace(Err(Error::illegal_state("Mutation result was too long!")))
                                .ok();
                        } else {
                            let actual = unsafe { core::slice::from_raw_parts_mut(data, max_size) };
                            actual[..target.as_slice().len()].copy_from_slice(target.as_slice());
                            new_size = target.as_slice().len();
                        }
                    };
                    return;
                }
            }
            self.result
                .replace(Err(Error::illegal_state(
                    "Couldn't borrow mutator while mutating!",
                )))
                .ok();
        });
        new_size
    }
}

/// A mutator which invokes a libFuzzer-like custom mutator or crossover.
///
/// The `CROSSOVER` constant
/// controls whether this mutator invokes `LLVMFuzzerCustomMutate` and `LLVMFuzzerCustomCrossover`.
/// You should avoid using crossover-like mutators with custom mutators as this may lead to the
/// injection of some input portions to another in ways which violate structure.
#[derive(Debug)]
pub struct LLVMCustomMutator<S, SM, const CROSSOVER: bool> {
    mutator: Rc<RefCell<SM>>,
    phantom: PhantomData<S>,
}

impl<S, SM> LLVMCustomMutator<S, SM, false> {
    /// Create the mutator which will invoke the custom mutator, emitting an error if the custom mutator is not present
    ///
    /// # Safety
    /// Will create the specified libfuzzer custom mutator `mutate` fn.
    /// Only safe if the custom mutator implementation is correct.
    pub unsafe fn mutate(mutator: SM) -> Result<Self, Error> {
        if libafl_targets_has_libfuzzer_custom_mutator() {
            Ok(Self::mutate_unchecked(mutator))
        } else {
            Err(Error::illegal_state(
                "Cowardly refusing to create a LLVMFuzzerMutator if a custom mutator is not defined.",
            ))
        }
    }

    /// Create the mutator which will invoke the custom mutator without checking if it exists first
    ///
    /// # Safety
    /// Will create the specified libfuzzer custom mutator and not check if it exists.
    /// Only safe if the custom mutator implementation is correct and exists.
    pub unsafe fn mutate_unchecked(mutator: SM) -> Self {
        LLVMCustomMutator {
            mutator: Rc::new(RefCell::new(mutator)),
            phantom: PhantomData,
        }
    }
}

impl<S, SM> LLVMCustomMutator<S, SM, true> {
    /// Create the mutator which will invoke the custom crossover, emitting an error if the custom crossover is not present
    ///
    /// # Safety
    /// Will create the specified libfuzzer custom crossover mutator.
    /// Only safe if the custom mutator crossover implementation is correct.
    pub unsafe fn crossover(mutator: SM) -> Result<Self, Error> {
        if libafl_targets_has_libfuzzer_custom_crossover() {
            Ok(Self::crossover_unchecked(mutator))
        } else {
            Err(Error::illegal_state(
                "Cowardly refusing to create a LLVMFuzzerMutator if a custom crossover is not defined.",
            ))
        }
    }

    /// Create the mutator which will invoke the custom crossover without checking if it exists first
    ///
    /// # Safety
    /// Will create the specified libfuzzer custom mutator crossover and not check if it exists.
    /// Only safe if the custom mutator crossover implementation is correct and exists.
    pub unsafe fn crossover_unchecked(mutator: SM) -> Self {
        LLVMCustomMutator {
            mutator: Rc::new(RefCell::new(mutator)),
            phantom: PhantomData,
        }
    }
}

impl<S, SM, const CROSSOVER: bool> ComposedByMutations for LLVMCustomMutator<S, SM, CROSSOVER>
where
    SM: ScheduledMutator<BytesInput, S>,
    SM::Mutations: MutatorsTuple<BytesInput, S>,
{
    type Mutations = SM::Mutations;
    fn mutations(&self) -> &Self::Mutations {
        unimplemented!("It is unsafe to provide reference-based access to the mutators as they are behind a RefCell.")
    }

    fn mutations_mut(&mut self) -> &mut Self::Mutations {
        unimplemented!("It is unsafe to provide reference-based access to the mutators as they are behind a RefCell.")
    }
}

impl<S, SM> Named for LLVMCustomMutator<S, SM, false> {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("LLVMCustomMutator");
        &NAME
    }
}

impl<S, SM> Mutator<BytesInput, S> for LLVMCustomMutator<S, SM, false>
where
    S: HasRand + HasMaxSize + 'static,
    SM: ScheduledMutator<BytesInput, S> + 'static,
    SM::Mutations: MutatorsTuple<BytesInput, S>,
{
    #[inline]
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input)
    }
}

impl<S, SM> ScheduledMutator<BytesInput, S> for LLVMCustomMutator<S, SM, false>
where
    SM: ScheduledMutator<BytesInput, S> + 'static,
    S: HasRand + HasMaxSize + 'static,
    SM::Mutations: MutatorsTuple<BytesInput, S>,
{
    fn iterations(&self, state: &mut S, input: &BytesInput) -> u64 {
        let mutator = self.mutator.deref().borrow();
        mutator.iterations(state, input)
    }

    fn schedule(&self, state: &mut S, input: &BytesInput) -> MutationId {
        let mutator = self.mutator.deref().borrow();
        mutator.schedule(state, input)
    }

    fn scheduled_mutate(
        &mut self,
        state: &mut S,
        input: &mut BytesInput,
    ) -> Result<MutationResult, Error> {
        let seed = state.rand_mut().next();
        let len_orig = input.bytes().len();
        let max_len = state.max_size();
        input.resize(max_len, 0);

        // we assume that the fuzzer did not use this mutator, but instead utilised their own
        let result = Rc::new(RefCell::new(Ok(MutationResult::Mutated)));
        let proxy = MutatorProxy::new(state, &self.mutator, &result);
        let old = MUTATOR.with(|mutator| {
            let mut mutator = mutator.borrow_mut();
            mutator.replace(Box::new(proxy.weak()))
        });
        let new_len = unsafe {
            libafl_targets_libfuzzer_custom_mutator(
                input.bytes_mut().as_mut_ptr(),
                len_orig,
                max_len,
                seed as u32,
            )
        };
        drop(proxy);
        MUTATOR.with(|mutator| {
            let mut mutator = mutator.borrow_mut();
            *mutator = old;
        });
        if result.deref().borrow().is_err() {
            return result.replace(Ok(MutationResult::Skipped));
        }

        if new_len > max_len {
            return Err(Error::illegal_state(format!("LLVMFuzzerCustomMutator returned more bytes than allowed. Expected up to {max_len} but got {new_len}")));
        }
        input.resize(new_len, 0);
        Ok(MutationResult::Mutated)
    }
}

impl<S, SM> Named for LLVMCustomMutator<S, SM, true> {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("LLVMCustomMutator");
        &NAME
    }
}

impl<S, SM> Mutator<BytesInput, S> for LLVMCustomMutator<S, SM, true>
where
    S: HasRand + HasMaxSize + HasCorpus + 'static,
    SM: ScheduledMutator<BytesInput, S> + 'static,
    S::Corpus: Corpus<Input = BytesInput>,
    SM::Mutations: MutatorsTuple<BytesInput, S>,
{
    #[inline]
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input)
    }
}

impl<S, SM> ScheduledMutator<BytesInput, S> for LLVMCustomMutator<S, SM, true>
where
    SM: ScheduledMutator<BytesInput, S> + 'static,
    S: HasRand + HasMaxSize + HasCorpus + 'static,
    S::Corpus: Corpus<Input = BytesInput>,
    SM::Mutations: MutatorsTuple<BytesInput, S>,
{
    fn iterations(&self, state: &mut S, input: &BytesInput) -> u64 {
        let mutator = self.mutator.deref().borrow();
        mutator.iterations(state, input)
    }

    fn schedule(&self, state: &mut S, input: &BytesInput) -> MutationId {
        let mutator = self.mutator.deref().borrow();
        mutator.schedule(state, input)
    }

    fn scheduled_mutate(
        &mut self,
        state: &mut S,
        input: &mut BytesInput,
    ) -> Result<MutationResult, Error> {
        let id = random_corpus_id_with_disabled!(state.corpus(), state.rand_mut());
        // We don't want to use the testcase we're already using for splicing
        if let Some(cur) = state.corpus().current() {
            if id == *cur {
                return Ok(MutationResult::Skipped);
            }
        }

        let mut other_testcase = state.corpus().get_from_all(id)?.borrow_mut();
        let other = other_testcase.load_input(state.corpus())?;
        let data2 = Vec::from(other.bytes());
        drop(other_testcase);

        let seed = state.rand_mut().next();
        let mut out = vec![0u8; state.max_size()];

        let max_len = state.max_size();
        let len_orig = input.len();

        input.resize(max_len, 0);

        // we assume that the fuzzer did not use this mutator, but instead utilised their own
        let result = Rc::new(RefCell::new(Ok(MutationResult::Mutated)));
        let proxy = MutatorProxy::new(state, &self.mutator, &result);
        let old = MUTATOR.with(|mutator| {
            let mut mutator = mutator.borrow_mut();
            mutator.replace(Box::new(proxy.weak()))
        });
        let new_len = unsafe {
            libafl_targets_libfuzzer_custom_crossover(
                input.bytes_mut().as_mut_ptr(),
                len_orig,
                data2.as_ptr(),
                data2.len(),
                out.as_mut_ptr(),
                max_len,
                seed as u32,
            )
        };
        drop(proxy);
        MUTATOR.with(|mutator| {
            let mut mutator = mutator.borrow_mut();
            *mutator = old;
        });
        if result.deref().borrow().is_err() {
            return result.replace(Ok(MutationResult::Skipped));
        }

        if new_len > max_len {
            return Err(Error::illegal_state(format!("LLVMFuzzerCustomCrossOver returned more bytes than allowed. Expected up to {max_len} but got {new_len}")));
        }

        input.resize(new_len, 0);
        Ok(MutationResult::Mutated)
    }
}
