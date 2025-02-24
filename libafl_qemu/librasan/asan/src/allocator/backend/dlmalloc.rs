//! # dlmalloc
//! This allocator makes use of the `dlmalloc` crate to manage memory. It in
//! turn uses pages of memory allocated by one of the implementations of the
//! `Mmap` trait described in the `mmap` module.
use alloc::fmt::{self, Debug, Formatter};
use core::{marker::PhantomData, mem::forget, ptr::null_mut};

use dlmalloc::{Allocator, Dlmalloc};
use log::debug;
use thiserror::Error;

use crate::{allocator::backend::AllocatorBackend, mmap::Mmap, GuestAddr};

pub struct DlmallocBackendMap<M: Mmap> {
    page_size: usize,
    _phantom: PhantomData<M>,
}

unsafe impl<M: Mmap + Send> Allocator for DlmallocBackendMap<M> {
    fn alloc(&self, size: usize) -> (*mut u8, usize, u32) {
        let map = M::map(size);
        match map {
            Ok(mut map) => {
                let slice = map.as_mut_slice();
                let result = (slice.as_mut_ptr(), slice.len(), 0);
                forget(map);
                result
            }
            Err(e) => {
                debug!("alloc failed: {:#?}", e);
                (null_mut(), 0, 0)
            }
        }
    }

    fn remap(&self, _ptr: *mut u8, _oldsize: usize, _newsize: usize, _can_move: bool) -> *mut u8 {
        null_mut()
    }

    fn free_part(&self, _ptr: *mut u8, _oldsize: usize, _newsize: usize) -> bool {
        false
    }

    fn free(&self, _ptr: *mut u8, _size: usize) -> bool {
        false
    }

    fn can_release_part(&self, _flags: u32) -> bool {
        false
    }

    fn allocates_zeros(&self) -> bool {
        true
    }

    fn page_size(&self) -> usize {
        self.page_size
    }
}

impl<M: Mmap> DlmallocBackendMap<M> {
    pub const fn new(page_size: usize) -> DlmallocBackendMap<M> {
        DlmallocBackendMap {
            page_size,
            _phantom: PhantomData,
        }
    }
}

pub struct DlmallocBackend<M: Mmap> {
    dlmalloc: Dlmalloc<DlmallocBackendMap<M>>,
}

impl<M: Mmap + Send> Debug for DlmallocBackend<M> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "DlmallocBackend")
    }
}

impl<M: Mmap + Send> AllocatorBackend for DlmallocBackend<M> {
    type Error = DlmallocBackendError;

    fn alloc(&mut self, size: usize, align: usize) -> Result<GuestAddr, DlmallocBackendError> {
        let ptr = unsafe { self.dlmalloc.malloc(size, align) };
        if ptr.is_null() {
            Err(DlmallocBackendError::FailedToAllocate(size, align))?;
        }
        Ok(ptr as GuestAddr)
    }

    fn dealloc(&mut self, addr: GuestAddr, size: usize, align: usize) -> Result<(), Self::Error> {
        unsafe { self.dlmalloc.free(addr as *mut u8, size, align) }
        Ok(())
    }
}

impl<M: Mmap + Send> DlmallocBackend<M> {
    pub const fn new(page_size: usize) -> DlmallocBackend<M> {
        let backend = DlmallocBackendMap::new(page_size);
        let dlmalloc = Dlmalloc::<DlmallocBackendMap<M>>::new_with_allocator(backend);
        Self { dlmalloc }
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum DlmallocBackendError {
    #[error("Failed to allocate - size: {0}, align: {1}")]
    FailedToAllocate(usize, usize),
}
