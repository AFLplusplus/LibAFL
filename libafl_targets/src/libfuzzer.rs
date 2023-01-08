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
    corpus::Corpus,
    inputs::{BytesInput, HasBytesVec, UsesInput},
    mutators::{ComposedByMutations, MutationResult, Mutator, MutatorsTuple, ScheduledMutator},
    state::{HasCorpus, HasMaxSize, HasRand},
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

pub fn has_custom_mutator() -> bool {
    unsafe { libafl_targets_has_libfuzzer_custom_mutator() }
}

pub fn has_custom_crossover() -> bool {
    unsafe { libafl_targets_has_libfuzzer_custom_crossover() }
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

struct MutatorProxy<'a, M, MT, S> {
    state: Rc<RefCell<*mut S>>, // refcell to prevent double-mutability over the pointer
    mutator: Weak<RefCell<M>>,
    result: Rc<RefCell<Result<MutationResult, Error>>>,
    stage_idx: i32,
    phantom: PhantomData<(&'a mut (), MT)>,
}

impl<'a, M, MT, S> MutatorProxy<'a, M, MT, S> {
    fn new(
        state: &'a mut S,
        mutator: &Rc<RefCell<M>>,
        result: &Rc<RefCell<Result<MutationResult, Error>>>,
        stage_idx: i32,
    ) -> Self {
        Self {
            state: Rc::new(RefCell::new(state)),
            mutator: Rc::downgrade(mutator),
            result: result.clone(),
            stage_idx,
            phantom: PhantomData,
        }
    }

    fn weak(
        &self,
    ) -> WeakMutatorProxy<impl Fn(&mut dyn for<'b> FnMut(&'b mut S)) -> bool, M, MT, S> {
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
                return false;
            },
            mutator: self.mutator.clone(),
            stage_idx: self.stage_idx,
            result: self.result.clone(),
            phantom: PhantomData,
        }
    }
}

#[derive(Clone)]
struct WeakMutatorProxy<F, M, MT, S> {
    accessor: F,
    mutator: Weak<RefCell<M>>,
    stage_idx: i32,
    result: Rc<RefCell<Result<MutationResult, Error>>>,
    phantom: PhantomData<(MT, S)>,
}

impl<F, M, MT, S> ErasedLLVMFuzzerMutator for WeakMutatorProxy<F, M, MT, S>
where
    F: Fn(&mut dyn for<'b> FnMut(&'b mut S)) -> bool,
    M: ScheduledMutator<MT, S>,
    MT: MutatorsTuple<S>,
    S: HasMaxSize + UsesInput<Input = BytesInput>,
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
                    let res = mutator.scheduled_mutate(state, &mut intermediary, self.stage_idx);
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
            return;
        });
        return new_size;
    }
}

// we must implement crossover compatibility here because (according to libfuzzer)
// LLVMFuzzerCustomCrossover may use LLVMFuzzerMutate (wacky)
#[derive(Debug)]
pub struct LLVMCustomMutator<MT, SM, const CROSSOVER: bool> {
    mutator: Rc<RefCell<SM>>,
    phantom: PhantomData<MT>,
}

impl<MT, SM> LLVMCustomMutator<MT, SM, false> {
    pub fn mutate(mutator: SM) -> Result<Self, Error> {
        if unsafe { libafl_targets_has_libfuzzer_custom_mutator() } {
            Ok(unsafe { Self::mutate_unchecked(mutator) })
        } else {
            Err(Error::illegal_state(
                "Cowardly refusing to create a LLVMFuzzerMutator if a custom mutator is not defined.",
            ))
        }
    }

    pub unsafe fn mutate_unchecked(mutator: SM) -> Self {
        LLVMCustomMutator {
            mutator: Rc::new(RefCell::new(mutator)),
            phantom: PhantomData,
        }
    }
}

impl<MT, SM> LLVMCustomMutator<MT, SM, true> {
    pub fn crossover(mutator: SM) -> Result<Self, Error> {
        if unsafe { libafl_targets_has_libfuzzer_custom_crossover() } {
            Ok(unsafe { Self::crossover_unchecked(mutator) })
        } else {
            Err(Error::illegal_state(
                "Cowardly refusing to create a LLVMFuzzerMutator if a custom crossover is not defined.",
            ))
        }
    }

    pub unsafe fn crossover_unchecked(mutator: SM) -> Self {
        LLVMCustomMutator {
            mutator: Rc::new(RefCell::new(mutator)),
            phantom: PhantomData,
        }
    }
}

impl<MT, S, SM, const CROSSOVER: bool> ComposedByMutations<MT, S>
    for LLVMCustomMutator<MT, SM, CROSSOVER>
where
    MT: MutatorsTuple<S>,
    S: UsesInput<Input = BytesInput> + HasRand + HasMaxSize,
    SM: ScheduledMutator<MT, S>,
{
    fn mutations(&self) -> &MT {
        unimplemented!("It is unsafe to provide reference-based access to the mutators as they are behind a RefCell.")
    }

    fn mutations_mut(&mut self) -> &mut MT {
        unimplemented!("It is unsafe to provide reference-based access to the mutators as they are behind a RefCell.")
    }
}

impl<MT, S, SM> Mutator<S> for LLVMCustomMutator<MT, SM, false>
where
    MT: MutatorsTuple<S> + 'static,
    S: UsesInput<Input = BytesInput> + HasRand + HasMaxSize + 'static,
    SM: ScheduledMutator<MT, S> + 'static,
{
    #[inline]
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut S::Input,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input, stage_idx)
    }
}

impl<MT, S, SM> ScheduledMutator<MT, S> for LLVMCustomMutator<MT, SM, false>
where
    SM: ScheduledMutator<MT, S> + 'static,
    MT: MutatorsTuple<S> + 'static,
    S: UsesInput<Input = BytesInput> + HasRand + HasMaxSize + 'static,
{
    fn iterations(&self, state: &mut S, input: &S::Input) -> u64 {
        let mutator = self.mutator.deref().borrow();
        mutator.iterations(state, input)
    }

    fn schedule(&self, state: &mut S, input: &S::Input) -> usize {
        let mutator = self.mutator.deref().borrow();
        mutator.schedule(state, input)
    }

    fn scheduled_mutate(
        &mut self,
        state: &mut S,
        input: &mut S::Input,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let seed = state.rand_mut().next();
        let target = input.bytes();
        let mut bytes = Vec::with_capacity(state.max_size());
        bytes.extend_from_slice(target.as_slice());
        bytes.resize(state.max_size(), 0);

        let result = Rc::new(RefCell::new(Err(Error::illegal_state(
            "Never updated mutator proxy's result.",
        ))));
        let proxy = MutatorProxy::new(state, &self.mutator, &result, stage_idx);
        let old = MUTATOR.with(|mutator| {
            let mut mutator = mutator.borrow_mut();
            mutator.replace(Box::new(proxy.weak()))
        });
        let new_size = unsafe {
            libafl_targets_libfuzzer_custom_mutator(
                bytes.as_mut_ptr(),
                target.as_slice().len(),
                bytes.len(),
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
        bytes.truncate(new_size);
        core::mem::swap(input.bytes_mut(), &mut bytes);
        Ok(MutationResult::Mutated)
    }
}

impl<MT, S, SM> Mutator<S> for LLVMCustomMutator<MT, SM, true>
where
    MT: MutatorsTuple<S> + 'static,
    S: UsesInput<Input = BytesInput> + HasRand + HasMaxSize + HasCorpus + 'static,
    SM: ScheduledMutator<MT, S> + 'static,
{
    #[inline]
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut S::Input,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input, stage_idx)
    }
}

impl<MT, S, SM> ScheduledMutator<MT, S> for LLVMCustomMutator<MT, SM, true>
where
    SM: ScheduledMutator<MT, S> + 'static,
    MT: MutatorsTuple<S> + 'static,
    S: UsesInput<Input = BytesInput> + HasRand + HasMaxSize + HasCorpus + 'static,
{
    fn iterations(&self, state: &mut S, input: &S::Input) -> u64 {
        let mutator = self.mutator.deref().borrow();
        mutator.iterations(state, input)
    }

    fn schedule(&self, state: &mut S, input: &S::Input) -> usize {
        let mutator = self.mutator.deref().borrow();
        mutator.schedule(state, input)
    }

    fn scheduled_mutate(
        &mut self,
        state: &mut S,
        input: &mut S::Input,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        // We don't want to use the testcase we're already using for splicing
        let count = state.corpus().count();
        let idx = state.rand_mut().below(count as u64) as usize;
        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
                return Ok(MutationResult::Skipped);
            }
        }

        let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
        let other = other_testcase.load_input()?;
        let data2 = Vec::from(other.bytes());
        drop(other_testcase);

        let seed = state.rand_mut().next();
        let mut out = vec![0u8; state.max_size()];
        let data1 = input.bytes();

        let result = Rc::new(RefCell::new(Err(Error::illegal_state(
            "Never updated mutator proxy's result.",
        ))));
        let proxy = MutatorProxy::new(state, &self.mutator, &result, stage_idx);
        let old = MUTATOR.with(|mutator| {
            let mut mutator = mutator.borrow_mut();
            mutator.replace(Box::new(proxy.weak()))
        });
        let new_size = unsafe {
            libafl_targets_libfuzzer_custom_crossover(
                data1.as_ptr(),
                data1.len(),
                data2.as_ptr(),
                data2.len(),
                out.as_mut_ptr(),
                out.len(),
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
        out.truncate(new_size);
        core::mem::swap(input.bytes_mut(), &mut out);
        Ok(MutationResult::Mutated)
    }
}
