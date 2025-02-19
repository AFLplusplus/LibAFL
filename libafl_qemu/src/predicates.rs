use core::fmt;
use std::borrow::Cow;

use libafl::{
    corpus::Testcase,
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
    HasMetadata,
};
use libafl_bolts::Named;

use crate::{Edges, PredicatesMap, QemuMappingsCache, Tracer, IS_RCA};
#[derive(Debug, Clone, Copy, Default)]
pub struct PredicateFeedback {
    was_crash: bool,
}

impl Named for PredicateFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("predicates")
    }
}

impl PredicateFeedback {
    #[must_use]
    pub fn new() -> Self {
        Self { was_crash: false }
    }

    #[must_use]
    pub fn is_rca(&self) -> bool {
        unsafe { IS_RCA }
    }
}

impl<S> StateInitializer<S> for PredicateFeedback {}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for PredicateFeedback
where
    S: HasMetadata,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, libafl::Error> {
        if self.is_rca() {
            return Ok(false);
        }
        self.was_crash = exit_kind == &ExitKind::Crash;
        Ok(false)
    }
    fn append_metadata(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        _testcase: &mut Testcase<I>,
    ) -> Result<(), libafl::Error> {
        if self.is_rca() {
            return Ok(());
        }

        let tracer = state.metadata::<Tracer>().unwrap();
        // because of double borrow shit!
        // println!("{:#?}", self.tracking_ip);
        let mut edges = vec![];
        let mut maxes = vec![];
        let mut mins = vec![];
        // If both is in the tracking range, then add it

        // get the cache to check which addr, val ranges are suitable for adding to the map
        let cache = state.metadata::<QemuMappingsCache>()?;

        for e in tracer.edges() {
            if cache.is_text_ptr(e.0) && cache.is_text_ptr(e.1) {
                edges.push(*e);
            }
        }

        for (addr, ma) in tracer.maxmap() {
            let addr_is_text = cache.is_text_ptr(*addr);
            let value_is_stack = cache.is_stack_ptr(*ma);
            let value_is_executable = cache.is_executable_ptr(*ma);
            let value_is_heap = cache.is_heap_ptr(*ma);

            if !value_is_stack && addr_is_text && !value_is_executable && !value_is_heap {
                maxes.push((*addr, *ma));
            }
        }
        for (addr, mi) in tracer.minmap() {
            let addr_is_text = cache.is_text_ptr(*addr);
            let value_is_stack = cache.is_stack_ptr(*mi);
            let value_is_executable = cache.is_executable_ptr(*mi);
            let value_is_heap = cache.is_heap_ptr(*mi);

            if !value_is_stack && addr_is_text && !value_is_executable && !value_is_heap {
                mins.push((*addr, *mi));
            }
        }

        // now edit the map
        let map = state.metadata_mut::<PredicatesMap>()?;

        for e in edges {
            map.add_edges(e, self.was_crash);
        }
        for (addr, ma) in maxes {
            map.add_maxes(addr, ma, self.was_crash);
        }
        for (addr, mi) in mins {
            map.add_mins(addr, mi, self.was_crash);
        }
        Ok(())
    }
}

impl fmt::Display for Edges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Edges({:#x}, {:#x})", self.0, self.1)
    }
}
