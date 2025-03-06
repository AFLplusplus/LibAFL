//! Implementation for "SAND: Decoupling Sanitization from Fuzzing for Low Overhead"
//! Reference Implementation: <https://github.com/wtdcode/sand-aflpp>
//! Detailed docs: <https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/SAND.md>
//! Maintainer: Ziqiao Kong (<https://github.com/wtdcode>)
//! Preprint: <https://arxiv.org/abs/2402.16497> accepted by ICSE'25

use alloc::vec::Vec;
use core::marker::PhantomData;

use libafl_bolts::{
    AsIter, Error, Named, hash_std,
    tuples::{Handle, MatchName, MatchNameRef},
};

use super::{Executor, ExitKind, HasObservers, HasTimeout};
use crate::{HasNamedMetadata, observers::MapObserver};

/// Like ObserverTuples, a list of executors
pub trait ExecutorsTuple<EM, I, S, Z> {
    /// Execute the executors and stop if any of them returns a crash
    fn run_target_all(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error>;
}

/// Since in most cases, the executors types can not be determined during compilation
/// time (for instance, the number of executors might change), this implementation would
/// act as a small helper.
impl<E, EM, I, S, Z> ExecutorsTuple<EM, I, S, Z> for Vec<E>
where
    E: Executor<EM, I, S, Z>,
{
    fn run_target_all(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        let mut kind = ExitKind::Ok;
        for e in self.iter_mut() {
            kind = e.run_target(fuzzer, state, mgr, input)?;
            if kind == ExitKind::Crash {
                return Ok(kind);
            }
        }
        Ok(kind)
    }
}

impl<EM, I, S, Z> ExecutorsTuple<EM, I, S, Z> for () {
    fn run_target_all(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) -> Result<ExitKind, Error> {
        Ok(ExitKind::Ok)
    }
}

impl<Head, Tail, EM, I, S, Z> ExecutorsTuple<EM, I, S, Z> for (Head, Tail)
where
    Head: Executor<EM, I, S, Z>,
    Tail: ExecutorsTuple<EM, I, S, Z>,
{
    fn run_target_all(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        let kind = self.0.run_target(fuzzer, state, mgr, input)?;
        if kind == ExitKind::Crash {
            return Ok(kind);
        }
        self.1.run_target_all(fuzzer, state, mgr, input)
    }
}

/// The execution pattern of the SANDExecutor. The default value used in our paper is
/// [SANDExecutionPattern::SimplifiedTrace] and we by design don't include coverage
/// increasing pattern here as it will miss at least 25% bugs and easy enough to implement
/// by iterating the crash corpus.
#[derive(Debug, Clone, Default, Copy)]
pub enum SANDExecutionPattern {
    /// The simplified trace, captures ~92% bug triggering inputs with ~20% overhead
    /// on overage (less than 5% overhead on most targets during evaluation)
    #[default]
    SimplifiedTrace,
    /// The unique trace, captures ~99.9% bug-triggering inputs with more than >50% overhead.
    UniqueTrace,
}

/// The core SANDExecutor. It wraps another executor and a list of extra executors.
/// Please refer to [SAND.md](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/SAND.md) for
/// how to build `sand_executors`.
#[derive(Debug, Clone)]
pub struct SANDExecutor<E, ET, C, O> {
    executor: E,
    sand_executors: ET,
    bitmap: Vec<u8>,
    ob_ref: Handle<C>,
    pattern: SANDExecutionPattern,
    ph: PhantomData<O>,
}

impl<E, ET, C, O> SANDExecutor<E, ET, C, O>
where
    C: Named,
{
    fn bitmap_set(&mut self, idx: usize) {
        let bidx = idx % 8;
        let idx = (idx / 8) % self.bitmap.len();
        *self.bitmap.get_mut(idx).unwrap() |= 1u8 << bidx;
    }

    fn bitmap_read(&mut self, idx: usize) -> u8 {
        let bidx = idx % 8;
        let idx = (idx / 8) % self.bitmap.len();
        (self.bitmap[idx] >> bidx) & 1
    }

    /// Create a new [SANDExecutor]
    pub fn new(
        executor: E,
        sand_extra_executors: ET,
        observer_handle: Handle<C>,
        bitmap_size: usize,
        pattern: SANDExecutionPattern,
    ) -> Self {
        Self {
            executor,
            sand_executors: sand_extra_executors,
            bitmap: vec![0; bitmap_size],
            ob_ref: observer_handle,
            pattern,
            ph: PhantomData::default(),
        }
    }

    /// Create a new [SANDExecutor] using paper setup
    pub fn new_paper(executor: E, sand_extra_executors: ET, observer_handle: Handle<C>) -> Self {
        Self::new(
            executor,
            sand_extra_executors,
            observer_handle,
            1 << 29,
            SANDExecutionPattern::SimplifiedTrace,
        )
    }
}

impl<E, ET, C, O> HasTimeout for SANDExecutor<E, ET, C, O>
where
    E: HasTimeout,
{
    fn timeout(&self) -> core::time::Duration {
        self.executor.timeout()
    }

    fn set_timeout(&mut self, timeout: core::time::Duration) {
        self.executor.set_timeout(timeout);
    }
}

impl<E, ET, C, O> HasObservers for SANDExecutor<E, ET, C, O>
where
    E: HasObservers,
{
    type Observers = E::Observers;
    fn observers(&self) -> libafl_bolts::tuples::RefIndexable<&Self::Observers, Self::Observers> {
        self.executor.observers()
    }

    fn observers_mut(
        &mut self,
    ) -> libafl_bolts::tuples::RefIndexable<&mut Self::Observers, Self::Observers> {
        self.executor.observers_mut()
    }
}

impl<E, ET, C, O, EM, I, S, Z, OT> Executor<EM, I, S, Z> for SANDExecutor<E, ET, C, O>
where
    ET: ExecutorsTuple<EM, I, S, Z>,
    E: Executor<EM, I, S, Z> + HasObservers<Observers = OT>,
    OT: MatchName,
    O: MapObserver<Entry = u8> + for<'it> AsIter<'it, Item = u8>,
    C: AsRef<O> + Named,
    S: HasNamedMetadata,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        let kind = self.executor.run_target(fuzzer, state, mgr, input)?;
        let ot = self.executor.observers();
        let ob = ot.get(&self.ob_ref).unwrap().as_ref();
        let initial = ob.initial();
        let covs = match self.pattern {
            SANDExecutionPattern::SimplifiedTrace => ob
                .as_iter()
                .map(|x| if *x == initial { 0x1 } else { 0x80 })
                .collect::<Vec<_>>(),
            SANDExecutionPattern::UniqueTrace => ob.to_vec(),
        };
        // Our paper uses xxh32 but it shouldn't have significant collision for most hashing algorithms.
        let pattern_hash = hash_std(&covs) as usize;

        let ret = if kind == ExitKind::Ok {
            if self.bitmap_read(pattern_hash) == 0 {
                let sand_kind = self.sand_executors.run_target_all(fuzzer, state, mgr, input)?;
                if sand_kind == ExitKind::Crash {
                    Ok(sand_kind)
                } else {
                    Ok(kind)
                }
            } else {
                Ok(kind)
            }
        } else {
            Ok(kind)
        };

        self.bitmap_set(pattern_hash);
        ret
    }
}
