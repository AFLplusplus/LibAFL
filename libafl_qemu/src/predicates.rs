use core::fmt;
use std::borrow::Cow;

use libafl::{executors::ExitKind, observers::Observer, Error, HasMetadata};
use libafl_bolts::Named;
use serde::{Deserialize, Serialize};

use crate::{Edges, PredicatesMap, QemuMappingsCache, Tracer, IS_RCA};
/// Observe prdicates
#[derive(Debug, Serialize, Deserialize)]
pub struct PredicateObserver {}

impl PredicateObserver {
    #[expect(clippy::unused_self)]
    fn is_rca(&self) -> bool {
        unsafe { IS_RCA }
    }
}

impl Named for PredicateObserver {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("PredicateObserver");
        &NAME
    }
}

impl<I, S> Observer<I, S> for PredicateObserver
where
    S: HasMetadata,
{
    fn pre_exec(&mut self, state: &mut S, _input: &I) -> Result<(), Error> {
        if !self.is_rca() {
            return Ok(());
        }

        if let Ok(meta) = state.metadata_mut::<Tracer>() {
            meta.clear();
        } else {
            state.add_metadata(Tracer::new());
        }
        Ok(())
    }

    fn post_exec(&mut self, state: &mut S, _input: &I, exit_kind: &ExitKind) -> Result<(), Error> {
        if !self.is_rca() {
            return Ok(());
        }

        let was_crash = exit_kind == &ExitKind::Crash;

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
            map.add_edges(e, was_crash);
        }
        for (addr, ma) in maxes {
            map.add_maxes(addr, ma, was_crash);
        }
        for (addr, mi) in mins {
            map.add_mins(addr, mi, was_crash);
        }
        Ok(())
    }
}

impl fmt::Display for Edges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Edges({:#x}, {:#x})", self.0, self.1)
    }
}
