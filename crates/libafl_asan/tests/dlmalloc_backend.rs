#[cfg(all(test, feature = "linux", target_os = "linux", feature = "dlmalloc"))]
mod tests {

    use std::{
        alloc::{GlobalAlloc, Layout},
        sync::Mutex,
    };

    use libafl_asan::{allocator::backend::dlmalloc::DlmallocBackend, mmap::linux::LinuxMmap};
    use spin::Lazy;

    static INIT_ONCE: Lazy<Mutex<()>> = Lazy::new(|| {
        {
            env_logger::init();
        };
        Mutex::new(())
    });

    const PAGE_SIZE: usize = 4096;

    fn allocator() -> DlmallocBackend<LinuxMmap> {
        drop(INIT_ONCE.lock().unwrap());
        DlmallocBackend::<LinuxMmap>::new(PAGE_SIZE)
    }

    #[test]
    fn test_allocate() {
        let allocator = allocator();
        let layout = Layout::from_size_align(16, 8).unwrap();
        let buf = unsafe { allocator.alloc(layout) };
        assert!(!buf.is_null());
        unsafe { allocator.dealloc(buf, layout) };
    }
}
