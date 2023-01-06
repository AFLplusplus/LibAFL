//! [`Libfuzzer`](https://www.llvm.org/docs/LibFuzzer.html)-style runtime wrapper for `LibAFL`.
//! This makes `LibAFL` interoperable with harnesses written for other fuzzers like `Libfuzzer` and [`AFLplusplus`](aflplus.plus).
//! We will interact with a C++ target, so use external c functionality

use alloc::{
    boxed::Box,
    rc::{Rc, Weak},
    string::String,
    vec::Vec,
};
use core::{
    cell::RefCell,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use libafl::{
    bolts::{rands::Rand, AsSlice},
    inputs::{BytesInput, HasBytesVec, HasTargetBytes, UsesInput},
    mutators::{MutationResult, Mutator},
    state::{HasMaxSize, HasRand},
    Error,
};

extern "C" {
    // int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32;

    // libafl_targets_libfuzzer_init calls LLVMFuzzerInitialize()
    fn libafl_targets_libfuzzer_init(argc: *const i32, argv: *const *const *const u8) -> i32;

    fn libafl_targets_has_libfuzzer_custom_mutator() -> bool;
    fn libafl_targets_libfuzzer_custom_mutator(
        data: *mut u8,
        size: usize,
        max_size: usize,
        seed: u32,
    ) -> usize;

    fn libafl_targets_has_libfuzzer_custom_crossover() -> bool;
    #[allow(unused)] // TODO remove
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

/// Calls the (native) libfuzzer initialize function.
/// Returns the value returned by the init function.
/// # Note
/// Calls the libfuzzer-style init function which is native code.
#[allow(clippy::similar_names)]
#[allow(clippy::must_use_candidate)] // nobody uses that return code...
pub fn libfuzzer_initialize(args: &[String]) -> i32 {
    let args: Vec<String> = args.iter().map(|x| x.clone() + "\0").collect();
    let argv: Vec<*const u8> = args.iter().map(|x| x.as_bytes().as_ptr()).collect();
    assert!(argv.len() < i32::MAX as usize);
    #[allow(clippy::cast_possible_wrap)]
    let argc = argv.len() as i32;
    unsafe {
        let argv_ptr = argv.as_ptr();
        libafl_targets_libfuzzer_init(core::ptr::addr_of!(argc), core::ptr::addr_of!(argv_ptr))
    }
}

/// Call a single input of a libfuzzer-style cpp-harness
/// # Note
/// Calls the libfuzzer harness. We actually think the target is unsafe and crashes eventually, that's why we do all this fuzzing.
#[allow(clippy::must_use_candidate)]
pub fn libfuzzer_test_one_input(buf: &[u8]) -> i32 {
    unsafe { LLVMFuzzerTestOneInput(buf.as_ptr(), buf.len()) }
}

trait ErasedLLVMFuzzerMutator {
    fn mutate(&self, data: *mut u8, size: usize, max_size: usize) -> usize;
}

thread_local! {
    static MUTATOR: RefCell<Option<Box<dyn ErasedLLVMFuzzerMutator>>> = RefCell::new(None);
}

#[allow(non_snake_case)]
#[no_mangle]
pub fn LLVMFuzzerMutate(data: *mut u8, size: usize, max_size: usize) -> usize {
    MUTATOR.with(|mutator| {
        if let Ok(mut mutator) = mutator.try_borrow_mut() {
            if let Some(mutator) = mutator.deref_mut() {
                return mutator.mutate(data, size, max_size);
            }
        }
        unreachable!("Couldn't get mutator!");
    })
}

struct MutatorProxy<'a, M, S: 'static> {
    state: Rc<RefCell<&'static mut S>>,
    mutator: Weak<RefCell<M>>,
    result: Rc<RefCell<Result<MutationResult, Error>>>,
    stage_idx: i32,
    phantom: PhantomData<&'a mut ()>,
}

impl<'a, M, S: 'static> MutatorProxy<'a, M, S> {
    fn new(
        state: &'a mut S,
        mutator: &Rc<RefCell<M>>,
        result: &Rc<RefCell<Result<MutationResult, Error>>>,
        stage_idx: i32,
    ) -> Self {
        Self {
            state: Rc::new(RefCell::new(unsafe { core::mem::transmute(state) })),
            mutator: Rc::downgrade(mutator),
            result: result.clone(),
            stage_idx,
            phantom: PhantomData,
        }
    }

    fn weak(&self) -> WeakMutatorProxy<M, S> {
        WeakMutatorProxy {
            state: Rc::downgrade(&self.state),
            mutator: self.mutator.clone(),
            stage_idx: self.stage_idx,
            result: self.result.clone(),
        }
    }
}

#[derive(Clone)]
struct WeakMutatorProxy<M, S: 'static> {
    state: Weak<RefCell<&'static mut S>>,
    mutator: Weak<RefCell<M>>,
    stage_idx: i32,
    result: Rc<RefCell<Result<MutationResult, Error>>>,
}

impl<M, S> ErasedLLVMFuzzerMutator for WeakMutatorProxy<M, S>
where
    M: Mutator<S>,
    S: HasMaxSize + UsesInput<Input = BytesInput> + 'static,
{
    fn mutate(&self, data: *mut u8, size: usize, max_size: usize) -> usize {
        if let Some(state) = self.state.upgrade() {
            if let Ok(mut state) = state.try_borrow_mut() {
                if let Some(mutator) = self.mutator.upgrade() {
                    if let Ok(mut mutator) = mutator.try_borrow_mut() {
                        let mut intermediary =
                            BytesInput::from(unsafe { core::slice::from_raw_parts(data, size) });
                        let old = state.deref_mut().max_size();
                        state.deref_mut().set_max_size(max_size);
                        let res = mutator.mutate(*state, &mut intermediary, self.stage_idx);
                        state.deref_mut().set_max_size(old);
                        let succeeded = res.is_ok();

                        let mut result = self.result.deref().borrow_mut();
                        *result = res;
                        drop(result);

                        return if succeeded {
                            let target = intermediary.target_bytes();
                            if target.as_slice().len() > max_size {
                                self.result
                                    .replace(Err(Error::illegal_state(
                                        "Mutation result was too long!",
                                    )))
                                    .ok();
                                return 0;
                            }
                            let actual = unsafe { core::slice::from_raw_parts_mut(data, max_size) };
                            actual[..target.as_slice().len()].copy_from_slice(target.as_slice());
                            target.as_slice().len()
                        } else {
                            0
                        };
                    }
                }
                self.result
                    .replace(Err(Error::illegal_state(
                        "Couldn't borrow mutator while mutating!",
                    )))
                    .ok();
                return 0;
            }
        }
        self.result
            .replace(Err(Error::illegal_state(
                "Couldn't borrow state while mutating!",
            )))
            .ok();
        return 0;
    }
}

#[derive(Debug)]
pub struct LLVMFuzzerMutator<M> {
    mutator: Rc<RefCell<M>>,
}

impl<M> LLVMFuzzerMutator<M> {
    pub fn new(mutator: M) -> Result<Self, Error> {
        if unsafe { libafl_targets_has_libfuzzer_custom_mutator() } {
            Ok(LLVMFuzzerMutator {
                mutator: Rc::new(RefCell::new(mutator)),
            })
        } else {
            Err(Error::illegal_state(
                "Cowardly refusing to create a LLVMFuzzerMutator if a custom mutator is not defined.",
            ))
        }
    }
}

impl<M, S> Mutator<S> for LLVMFuzzerMutator<M>
where
    M: Mutator<S> + 'static,
    S: HasRand + HasMaxSize + UsesInput<Input = BytesInput> + 'static,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut BytesInput,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let seed = state.rand_mut().next();
        let result = Rc::new(RefCell::new(Err(Error::illegal_state(
            "Never updated mutator proxy's result.",
        ))));
        let proxy = MutatorProxy::new(state, &self.mutator, &result, stage_idx);
        MUTATOR.with(|mutator| {
            let mut mutator = mutator.borrow_mut();
            if let Some(mutator) = mutator.deref_mut() {
                *mutator = Box::new(proxy.weak());
            } else {
                let _ = mutator.insert(Box::new(proxy.weak()));
            }
        });
        let target = input.target_bytes();
        let mut bytes = Vec::with_capacity(state.max_size());
        bytes.extend_from_slice(target.as_slice());
        bytes.resize(state.max_size(), 0);
        let new_size = unsafe {
            libafl_targets_libfuzzer_custom_mutator(
                bytes.as_mut_ptr(),
                target.as_slice().len(),
                bytes.len(),
                seed as u32,
            )
        };
        if result.deref().borrow().is_err() {
            return result.replace(Ok(MutationResult::Skipped));
        }
        bytes.truncate(new_size);
        core::mem::swap(input.bytes_mut(), &mut bytes);
        Ok(MutationResult::Mutated)
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        stage_idx: i32,
        corpus_idx: Option<usize>,
    ) -> Result<(), Error> {
        let mut mutator = self.mutator.deref().borrow_mut();
        mutator.post_exec(state, stage_idx, corpus_idx)
    }
}

#[derive(Debug)]
pub struct LLVMCrossoverStage<S> {
    phantom: PhantomData<S>,
}

impl<S> LLVMCrossoverStage<S> {
    pub fn new() -> Result<Self, Error> {
        if unsafe { libafl_targets_has_libfuzzer_custom_crossover() } {
            Ok(Self {
                phantom: PhantomData,
            })
        } else {
            Err(Error::illegal_state("Cowardly refusing to create a LLVMCrossoverStage if a custom crossover is not defined."))
        }
    }
}

// TODO implement the crossover stage similar to how libfuzzer might implement it, using the custom crossover
