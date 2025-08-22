use alloc::vec::{IntoIter, Vec};
use core::fmt::Debug;

use itertools::Itertools;
use thiserror::Error;

use crate::{
    GuestAddr,
    maps::entry::{MapEntry, WriteableMapProtection},
    mmap::Mmap,
};

mod decode;
pub mod entry;

pub mod iterator;

pub struct Maps {
    maps: Vec<MapEntry>,
}

impl Maps {
    pub fn new(maps: Vec<MapEntry>) -> Self {
        Self { maps }
    }

    pub fn writeable<M: Mmap>(
        &self,
        addr: GuestAddr,
    ) -> Result<WriteableMapProtection<'_, M>, MapsError<M>> {
        let mapping = self
            .maps
            .iter()
            .filter(|m| m.contains(addr))
            .exactly_one()
            .map_err(|_e| MapsError::MappingNotFound(addr))?;
        mapping
            .writeable::<M>()
            .map_err(|e| MapsError::MmapError(e))
    }
}

impl IntoIterator for Maps {
    type Item = MapEntry;
    type IntoIter = IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        self.maps.into_iter()
    }
}

#[derive(Error, Debug)]
pub enum MapsError<M: Mmap> {
    #[error("Mapping not found: {0}")]
    MappingNotFound(GuestAddr),
    #[error("Mmap error: {0:?}")]
    MmapError(M::Error),
}
