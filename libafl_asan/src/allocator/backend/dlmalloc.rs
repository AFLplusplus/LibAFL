//! # dlmalloc
//! This allocator makes use of the `dlmalloc` crate to manage memory. It in
//! turn uses pages of memory allocated by one of the implementations of the
//! `Mmap` trait described in the `mmap` module.
use alloc::{
    alloc::{GlobalAlloc, Layout},
    fmt::{self, Debug, Formatter},
};
use core::{marker::PhantomData, mem::forget, ptr::null_mut};

use dlmalloc::{Allocator, Dlmalloc};
use log::debug;
use spin::Mutex;

use crate::mmap::Mmap;

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
                debug!("alloc failed: {e:#?}");
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
    dlmalloc: Mutex<Dlmalloc<DlmallocBackendMap<M>>>,
}

impl<M: Mmap + Send> DlmallocBackend<M> {
    pub const fn new(page_size: usize) -> DlmallocBackend<M> {
        let backend = DlmallocBackendMap::new(page_size);
        let dlmalloc = Dlmalloc::<DlmallocBackendMap<M>>::new_with_allocator(backend);
        Self {
            dlmalloc: Mutex::new(dlmalloc),
        }
    }
}

impl<M: Mmap + Send> Debug for DlmallocBackend<M> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "DlmallocBackend")
    }
}

unsafe impl<M: Mmap> GlobalAlloc for DlmallocBackend<M> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { self.dlmalloc.lock().malloc(layout.size(), layout.align()) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            self.dlmalloc
                .lock()
                .free(ptr, layout.size(), layout.align())
        }
    }
}
