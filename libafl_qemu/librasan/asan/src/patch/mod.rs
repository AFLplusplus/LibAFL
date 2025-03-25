//! # patch
//! This module provides implementations patching function prologues in order
//! to re-direct execution to an alternative address.
pub mod raw;

use alloc::{collections::BTreeMap, fmt::Debug};

use log::trace;
use spin::{Mutex, MutexGuard, Once};
use thiserror::Error;

use crate::{
    GuestAddr,
    maps::{Maps, MapsError},
    mmap::Mmap,
};

pub trait Patch: Debug {
    type Error: Debug;
    fn patch(target: GuestAddr, destination: GuestAddr) -> Result<(), Self::Error>;
}

static PATCHED: Once<Mutex<Patches>> = Once::new();

pub struct Patches {
    maps: Maps,
    patches: BTreeMap<GuestAddr, GuestAddr>,
}

impl Patches {
    pub fn init(maps: Maps) {
        let patches = Mutex::new(Patches {
            maps,
            patches: BTreeMap::new(),
        });
        PATCHED.call_once(|| patches);
    }

    fn get() -> Option<MutexGuard<'static, Patches>> {
        PATCHED.get().map(|m| m.lock())
    }

    pub fn apply<P: Patch, M: Mmap>(
        target: GuestAddr,
        destination: GuestAddr,
    ) -> Result<(), PatchesError<P, M>> {
        trace!("patch: {:#x} -> {:#x}", target, destination);
        let mut patches = Patches::get().ok_or(PatchesError::Uninitialized())?;
        let prot = patches
            .maps
            .writeable(target)
            .map_err(PatchesError::MapsError)?;
        P::patch(target, destination).map_err(|e| PatchesError::PatchError(e))?;
        drop(prot);
        patches.patches.insert(target, destination);
        Ok(())
    }

    pub fn is_patched(addr: GuestAddr) -> bool {
        Self::get().is_some_and(|patches| patches.patches.contains_key(&addr))
    }
}

#[derive(Error, Debug)]
pub enum PatchesError<P: Patch, M: Mmap> {
    #[error("Uninitialized")]
    Uninitialized(),
    #[error("Patch error: {0:?}")]
    PatchError(P::Error),
    #[error("Maps error: {0:?}")]
    MapsError(MapsError<M>),
}
