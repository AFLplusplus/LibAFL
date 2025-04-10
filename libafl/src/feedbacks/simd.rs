//! SIMD accelerated map feedback with stable Rust.

use alloc::{borrow::Cow, vec::Vec};
use core::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use libafl_bolts::{
    AsIter, AsSlice, Error, Named,
    simd::{
        covmap_is_interesting_naive, covmap_is_interesting_u8x16, covmap_is_interesting_u8x32,
        std_covmap_is_interesting,
    },
    tuples::{Handle, MatchName},
};
use serde::{Serialize, de::DeserializeOwned};

use super::{
    DifferentIsNovel, Feedback, HasObserverHandle, MapFeedback, MaxReducer, StateInitializer,
};
#[cfg(feature = "introspection")]
use crate::state::HasClientPerfMonitor;
use crate::{
    HasNamedMetadata,
    corpus::Testcase,
    events::EventFirer,
    executors::ExitKind,
    observers::{CanTrack, MapObserver},
    state::HasExecutions,
};

/// The coverage map SIMD acceleration to use.
/// Benchmark is available at <https://github.com/wtdcode/libafl_simd_bench>
#[derive(Debug, Clone, Default, Copy)]
pub enum SimdImplmentation {
    /// The u8x16 implementation from wide, usually the fastest
    #[default]
    WideU8x16,
    /// The u8x32 implementation from wide, slightly slower than u8x16 (~1%)
    WideU8x32,
    /// Naive implementation, reference only
    Naive,
}

impl SimdImplmentation {
    fn dispatch_simd(self) -> CoverageMapFunPtr {
        match self {
            SimdImplmentation::WideU8x16 => covmap_is_interesting_u8x16,
            SimdImplmentation::WideU8x32 => covmap_is_interesting_u8x32,
            SimdImplmentation::Naive => covmap_is_interesting_naive,
        }
    }
}

type CoverageMapFunPtr = fn(&[u8], &[u8], bool) -> (bool, Vec<usize>);

/// Stable Rust wrapper for SIMD accelerated map feedback. Unfortunately, we have to
/// keep this until specialization is stablized (not yet since 2016).
#[derive(Debug, Clone)]
pub struct SimdMapFeedback<C, O> {
    map: MapFeedback<C, DifferentIsNovel, O, MaxReducer>,
    simd: CoverageMapFunPtr,
}

impl<C, O> SimdMapFeedback<C, O> {
    /// Wraps an existing map and enable SIMD acceleration. This will use standard SIMD
    /// implementation, which might vary based on target architecture according to our
    /// benchmark.
    #[must_use]
    pub fn new(map: MapFeedback<C, DifferentIsNovel, O, MaxReducer>) -> Self {
        Self {
            map,
            simd: std_covmap_is_interesting,
        }
    }

    /// Wraps an existing map and enable SIMD acceleration according to arguments.
    #[must_use]
    pub fn with_simd(
        map: MapFeedback<C, DifferentIsNovel, O, MaxReducer>,
        simd: SimdImplmentation,
    ) -> Self {
        Self {
            map,
            simd: simd.dispatch_simd(),
        }
    }
}

impl<C, O> Deref for SimdMapFeedback<C, O> {
    type Target = MapFeedback<C, DifferentIsNovel, O, MaxReducer>;
    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl<C, O> DerefMut for SimdMapFeedback<C, O> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.map
    }
}

impl<C, O, S> StateInitializer<S> for SimdMapFeedback<C, O>
where
    O: MapObserver,
    O::Entry: 'static + Default + Debug + DeserializeOwned + Serialize,
    S: HasNamedMetadata,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        self.map.init_state(state)
    }
}

impl<C, O> HasObserverHandle for SimdMapFeedback<C, O> {
    type Observer = C;

    #[inline]
    fn observer_handle(&self) -> &Handle<C> {
        self.map.observer_handle()
    }
}

impl<C, O> Named for SimdMapFeedback<C, O> {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        self.map.name()
    }
}

// Delegate implementations to inner mapping except is_interesting
impl<C, O, EM, I, OT, S> Feedback<EM, I, OT, S> for SimdMapFeedback<C, O>
where
    C: CanTrack + AsRef<O>,
    EM: EventFirer<I, S>,
    O: MapObserver<Entry = u8> + for<'a> AsSlice<'a, Entry = u8> + for<'a> AsIter<'a, Item = u8>,
    OT: MatchName,
    S: HasNamedMetadata + HasExecutions,
{
    fn is_interesting(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        let res = self
            .map
            .is_interesting_u8_simd_optimized(state, observers, self.simd);
        Ok(res)
    }

    #[cfg(feature = "introspection")]
    fn is_interesting_introspection(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        S: HasClientPerfMonitor,
    {
        self.map
            .is_interesting_introspection(state, manager, input, observers, exit_kind)
    }

    #[cfg(feature = "track_hit_feedbacks")]
    fn last_result(&self) -> Result<bool, Error> {
        // cargo +nightly doc asks so
        <MapFeedback<C, DifferentIsNovel, O, MaxReducer> as Feedback<EM, I, OT, S>>::last_result(
            &self.map,
        )
    }

    #[cfg(feature = "track_hit_feedbacks")]
    fn append_hit_feedbacks(&self, list: &mut Vec<Cow<'static, str>>) -> Result<(), Error> {
        // cargo +nightly doc asks so
        <MapFeedback<C, DifferentIsNovel, O, MaxReducer> as Feedback<EM, I, OT, S>>::append_hit_feedbacks(&self.map, list)
    }

    #[inline]
    fn append_metadata(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
        self.map
            .append_metadata(state, manager, observers, testcase)
    }
}
