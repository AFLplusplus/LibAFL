use jemallocator::Jemalloc;

use hashbrown::HashMap;
use nix::{
    libc::{memcpy, memmove, memset},
    sys::mman::{mmap, MapFlags, ProtFlags},
};

use libc::{RTLD_NEXT, _SC_PAGESIZE, dlsym, pthread_atfork, sysconf};
use std::{alloc::GlobalAlloc, cell::RefCell, cell::RefMut, ffi::c_void, ffi::CString};

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

static mut ALLOCATOR_SINGLETON: Option<RefCell<Allocator>> = None;

struct Allocator {
    page_size: usize,
    shadow_offset: usize,
    allocations: HashMap<usize, usize>,
}

impl Allocator {
    pub fn new() -> Self {
        Self {
            page_size: unsafe { sysconf(_SC_PAGESIZE) as usize },
            shadow_offset: 1 << 44,
            allocations: HashMap::new(),
        }
    }

    pub fn get() -> RefMut<'static, Allocator> {
        unsafe {
            match ALLOCATOR_SINGLETON.as_mut() {
                None => {
                    ALLOCATOR_SINGLETON = Some(RefCell::new(Allocator::new()));
                },
                _ => (),
            }

            // we need to loop in case there is a race between threads at init time.
            loop {
                match ALLOCATOR_SINGLETON.as_mut().unwrap().try_borrow_mut() {
                    Ok(allocref) => return allocref,
                    Err(_) => (),
                }
            }
        }
    }

    pub fn init(&self) {
        unsafe extern "C" fn atfork() {
            ALLOCATOR_SINGLETON = None;
            Allocator::get();
        }
        unsafe {
            pthread_atfork(None, None, Some(atfork));
        }
    }

    #[inline]
    fn round_up_to_page(&self, size: usize) -> usize {
        ((size + self.page_size) / self.page_size) * self.page_size
    }

    #[inline]
    fn round_down_to_page(&self, value: usize) -> usize {
        (value / self.page_size) * self.page_size
    }

    pub unsafe fn alloc(&mut self, size: usize, _alignment: usize) -> *mut c_void {
        //dbg!("in allocate");
        let rounded_up_size = self.round_up_to_page(size);

        let mapping = match mmap(
            0 as *mut c_void,
            rounded_up_size + 2 * self.page_size,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
            -1,
            0,
        ) {
            Ok(mapping) => mapping as usize,
            Err(err) => {
                println!("An error occurred while mapping memory: {:?}", err);
                return 0 as *mut c_void;
            }
        };

        let shadow_mapping_start = ((mapping + self.page_size) >> 3) + self.shadow_offset;

        let shadow_mapping = match mmap(
            self.round_down_to_page(shadow_mapping_start) as *mut c_void,
            self.round_up_to_page((rounded_up_size + 2 * self.page_size) / 8),
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED | MapFlags::MAP_PRIVATE,
            -1,
            0,
        ) {
            Ok(mapping) => mapping as usize,
            Err(err) => {
                println!("An error occurred while mapping shadow memory: {:?}", err);
                return 0 as *mut c_void;
            }
        };

        assert_eq!(
            shadow_mapping,
            self.round_down_to_page(shadow_mapping_start)
        );

        // unpoison the shadow memory for the allocation itself
        memset((shadow_mapping_start) as *mut c_void, 0xff, size / 8);

        self.allocations.insert(mapping + self.page_size, size);

        (mapping + self.page_size) as *mut c_void
    }

    pub unsafe fn release(&self, ptr: *mut c_void) {
        let size = match self.allocations.get(&(ptr as usize)) {
            Some(size) => size,
            None => return,
        };
        let shadow_mapping_start = (ptr as usize >> 3) + self.shadow_offset;

        // poison the shadow memory for the allocation
        memset(shadow_mapping_start as *mut c_void, 0x00, size / 8);
    }

    pub fn get_usable_size(&self, ptr: *mut c_void) -> usize {
        *self.allocations.get(&(ptr as usize)).unwrap()
    }
}

#[no_mangle]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    Allocator::get().alloc(size, 0x8)
}

#[no_mangle]
pub unsafe extern "C" fn pvalloc(size: usize) -> *mut c_void {
    Allocator::get().alloc(size, 0x8)
}

#[no_mangle]
pub unsafe extern "C" fn valloc(size: usize) -> *mut c_void {
    Allocator::get().alloc(size, 0x8)
}

#[no_mangle]
pub unsafe extern "C" fn calloc(nmemb: usize, size: usize) -> *mut c_void {
    Allocator::get().alloc(size * nmemb, 0x8)
}

#[no_mangle]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    let mut allocator = Allocator::get();
    let ret = allocator.alloc(size, 0x8);
    if ptr != 0 as *mut c_void {
        memmove(ret, ptr, allocator.get_usable_size(ptr));
    }
    allocator.release(ptr);
    ret
}

#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    if ptr != 0 as *mut c_void {
        Allocator::get().release(ptr);
    }
}

#[no_mangle]
pub unsafe extern "C" fn malloc_usable_size(ptr: *mut c_void) -> usize {
    Allocator::get().get_usable_size(ptr)
}

#[no_mangle]
pub unsafe extern "C" fn memalign(size: usize, alignment: usize) -> *mut c_void {
    Allocator::get().alloc(size, alignment)
}

#[no_mangle]
pub unsafe extern "C" fn posix_memalign(
    pptr: *mut *mut c_void,
    size: usize,
    alignment: usize,
) -> i32 {
    *pptr = Allocator::get().alloc(size, alignment);
    0
}

#[no_mangle]
pub unsafe extern "C" fn mallinfo() -> *mut c_void {
    0 as *mut c_void
}

#[no_mangle]
#[link_section = ".init_array"]
static LD_PRELOAD_INIT: extern "C" fn() = init;

extern "C" fn init() {
    Allocator::get().init();
}
