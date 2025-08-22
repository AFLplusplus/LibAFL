use alloc::alloc::{GlobalAlloc, Layout};

use baby_mimalloc::Mimalloc;
use spin::Mutex;

pub struct MimallocBackend<G: GlobalAlloc> {
    mimalloc: Mutex<Mimalloc<G>>,
}

impl<G: GlobalAlloc> MimallocBackend<G> {
    pub const fn new(global_allocator: G) -> Self {
        MimallocBackend {
            mimalloc: Mutex::new(Mimalloc::with_os_allocator(global_allocator)),
        }
    }
}

unsafe impl<G: GlobalAlloc> GlobalAlloc for MimallocBackend<G> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { self.mimalloc.lock().alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { self.mimalloc.lock().dealloc(ptr, layout) }
    }
}
