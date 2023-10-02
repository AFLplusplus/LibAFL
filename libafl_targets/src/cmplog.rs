//! `CmpLog` logs and reports back values touched during fuzzing.
//! The values will then be used in subsequent mutations.
//!

use alloc::string::{String, ToString};

use libafl::{
    executors::ExitKind,
    inputs::UsesInput,
    observers::{
        cmps::{
            cmp::{CmpLogInstruction, CmpLogMap, CmpLogVals},
            CmpLogHeader, CmpMap, CmpObserver, CmpValuesMetadata,
        },
        Observer,
    },
    state::HasMetadata,
    Error,
};
use libafl_bolts::{ownedref::OwnedMutPtr, Named};

use crate::{CMPLOG_MAP_H, CMPLOG_MAP_W};

// void __libafl_targets_cmplog_instructions(uintptr_t k, uint8_t shape, uint64_t arg1, uint64_t arg2)
extern "C" {
    /// Logs an instruction for feedback during fuzzing
    pub fn __libafl_targets_cmplog_instructions(k: usize, shape: u8, arg1: u64, arg2: u64);

    /// Pointer to the `CmpLog` map
    pub static mut libafl_cmplog_map_ptr: *mut CmpLogMap;
}

pub use libafl_cmplog_map_ptr as CMPLOG_MAP_PTR;

/// The global `CmpLog` map for the current `LibAFL` run.
#[no_mangle]
#[allow(clippy::large_stack_arrays)]
pub static mut libafl_cmplog_map: CmpLogMap = CmpLogMap {
    headers: [CmpLogHeader {
        hits: 0,
        shape: 0,
        kind: 0,
    }; CMPLOG_MAP_W],
    vals: CmpLogVals {
        operands: [[CmpLogInstruction(0, 0); CMPLOG_MAP_H]; CMPLOG_MAP_W],
    },
};

pub use libafl_cmplog_map as CMPLOG_MAP;

/// Value indicating if cmplog is enabled.
#[no_mangle]
pub static mut libafl_cmplog_enabled: u8 = 0;

pub use libafl_cmplog_enabled as CMPLOG_ENABLED;

/// A [`CmpObserver`] observer for `CmpLog`. This one is just the same as `StdCmpObserver` except that it toggles `CMPLOG_ENABLED`
#[derive(Debug)]
pub struct CmpLogObserver {
    map: OwnedMutPtr<CmpLogMap>,
    size: Option<OwnedMutPtr<usize>>,
    add_meta: bool,
    name: String,
}

impl<'a, S> CmpObserver<'a, CmpLogMap, S, CmpValuesMetadata> for CmpLogObserver
where
    S: UsesInput + HasMetadata,
{
    /// Get the number of usable cmps (all by default)
    fn usable_count(&self) -> usize {
        match &self.size {
            None => self.map.as_ref().len(),
            Some(o) => *o.as_ref(),
        }
    }

    fn cmp_map(&self) -> &CmpLogMap {
        self.map.as_ref()
    }

    fn cmp_map_mut(&mut self) -> &mut CmpLogMap {
        self.map.as_mut()
    }
}

impl<'a, S> Observer<S> for CmpLogObserver
where
    S: UsesInput + HasMetadata,
    Self: CmpObserver<'a, CmpLogMap, S, CmpValuesMetadata>,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.map.as_mut().reset()?;
        unsafe {
            CMPLOG_ENABLED = 1;
        }
        Ok(())
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        unsafe {
            CMPLOG_ENABLED = 0;
        }

        if self.add_meta {
            self.add_cmpvalues_meta(state);
        }

        Ok(())
    }
}

impl Named for CmpLogObserver {
    fn name(&self) -> &str {
        &self.name
    }
}

impl CmpLogObserver {
    /// Creates a new [`CmpLogObserver`] with the given map and name.
    ///
    /// # Safety
    /// Will keep a ptr to the map. The map may not move in memory!
    #[must_use]
    pub unsafe fn with_map_ptr(name: &'static str, map: *mut CmpLogMap, add_meta: bool) -> Self {
        Self {
            name: name.to_string(),
            size: None,
            add_meta,
            map: OwnedMutPtr::Ptr(map),
        }
    }

    /// Creates a new [`CmpLogObserver`] with the given name from the default [`CMPLOG_MAP`]
    #[must_use]
    pub fn new(name: &'static str, add_meta: bool) -> Self {
        unsafe { Self::with_map_ptr(name, libafl_cmplog_map_ptr, add_meta) }
    }

    // TODO with_size
}
