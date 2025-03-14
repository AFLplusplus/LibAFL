use alloc::{collections::BTreeMap, fmt::Debug, vec::Vec};
use core::ffi::{CStr, c_char};

use itertools::Itertools;
use log::{debug, trace};
use spin::Mutex;
use thiserror::Error;

use crate::{
    GuestAddr,
    hooks::PatchedHook,
    maps::{MapReader, entry::MapEntry, iterator::MapIterator},
    mmap::Mmap,
    patch::Patch,
    symbols::Symbols,
};

static PATCHED: Mutex<Option<BTreeMap<GuestAddr, PatchedHook>>> = Mutex::new(None);

pub struct PatchedHooks;

impl PatchedHooks {
    pub fn init<S: Symbols, P: Patch, R: MapReader, M: Mmap>()
    -> Result<(), PatchesError<S, P, R, M>> {
        debug!("Installing patches");
        let mappings = Self::get_mappings()?;
        mappings.iter().for_each(|m| trace!("{m:?}"));
        for patch in PatchedHook::all() {
            Self::patch(patch, &mappings)?;
        }
        debug!("Patching complete");
        Ok(())
    }

    pub fn get_mappings<S: Symbols, P: Patch, R: MapReader, M: Mmap>()
    -> Result<Vec<MapEntry>, PatchesError<S, P, R, M>> {
        let reader = R::new().map_err(|e| PatchesError::MapReaderError(e))?;
        Ok(MapIterator::new(reader).collect::<Vec<MapEntry>>())
    }

    pub fn patch<S: Symbols, P: Patch, R: MapReader, M: Mmap>(
        patch: PatchedHook,
        mappings: &[MapEntry],
    ) -> Result<(), PatchesError<S, P, R, M>> {
        trace!(
            "patch: {:?}, destination: {:#x}",
            patch.name, patch.destination
        );
        let target = S::lookup(patch.name.as_ptr() as *const c_char)
            .map_err(|e| PatchesError::SymbolsError(e))?;
        trace!("patching: {:#x} -> {:#x}", target, patch.destination);
        let mapping = mappings
            .iter()
            .filter(|m| m.contains(target))
            .exactly_one()
            .map_err(|_e| PatchesError::MapError(target))?;
        let prot = mapping
            .writeable::<M>()
            .map_err(|e| PatchesError::MmapError(e))?;
        P::patch(target, patch.destination).map_err(|e| PatchesError::PatchError(e))?;
        drop(prot);
        PATCHED.lock().get_or_insert_default().insert(target, patch);
        Ok(())
    }

    pub fn check_patched(addr: GuestAddr) -> Result<(), PatchesCheckError> {
        match PATCHED.lock().as_ref().and_then(|p| p.get(&addr)) {
            Some(patch) => Err(PatchesCheckError::AddressPatchedError(addr, patch.name))?,
            _ => Ok(()),
        }
    }
}

#[derive(Error, Debug, PartialEq, Clone)]
pub enum PatchesError<S: Symbols, P: Patch, R: MapReader, M: Mmap> {
    #[error("Symbols error: {0:?}")]
    SymbolsError(S::Error),
    #[error("Patch error: {0:?}")]
    PatchError(P::Error),
    #[error("Map reader error: {0:?}")]
    MapReaderError(R::Error),
    #[error("Map error: {0:?}")]
    MapError(GuestAddr),
    #[error("Mmap error: {0:?}")]
    MmapError(M::Error),
}

#[derive(Error, Debug, PartialEq, Clone)]
pub enum PatchesCheckError {
    #[error("Address: {0} is patched for {1:?}")]
    AddressPatchedError(GuestAddr, &'static CStr),
}
