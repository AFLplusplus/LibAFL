//! # patch
//! This module provides implementations patching function prologues in order
//! to re-direct execution to an alternative address.
pub mod raw;

use alloc::fmt::Debug;

use log::trace;
use spin::{Mutex, Once};
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

use core::hash::BuildHasherDefault;

use ahash::AHasher;
use hashbrown::HashMap;
type Hasher = BuildHasherDefault<AHasher>;

static PATCHES: Once<Mutex<Patches>> = Once::new();
static PATCHED: Once<Mutex<HashMap<GuestAddr, GuestAddr, Hasher>>> = Once::new();

pub struct Patches {
    maps: Maps,
}

impl Patches {
    pub fn init(maps: Maps) {
        let patches = Mutex::new(Patches { maps });
        PATCHES.call_once(|| patches);
        let patched = Mutex::new(HashMap::with_capacity_and_hasher(4096, Hasher::default()));
        PATCHED.call_once(|| patched);
    }

    pub fn apply<P: Patch, M: Mmap>(
        target: GuestAddr,
        destination: GuestAddr,
    ) -> Result<(), PatchesError<P, M>> {
        trace!("patch: {target:#x} -> {destination:#x}");
        let patches = PATCHES.get().ok_or(PatchesError::Uninitialized())?.lock();
        let prot = patches
            .maps
            .writeable(target)
            .map_err(PatchesError::MapsError)?;
        P::patch(target, destination).map_err(|e| PatchesError::PatchError(e))?;
        drop(prot);
        let mut patched = PATCHED.get().ok_or(PatchesError::Uninitialized())?.lock();
        patched.insert(target, destination);
        Ok(())
    }

    pub fn is_patched(addr: GuestAddr) -> bool {
        PATCHED.get().is_some_and(|p| p.lock().contains_key(&addr))
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
