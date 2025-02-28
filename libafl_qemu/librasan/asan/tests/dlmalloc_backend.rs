#[cfg(test)]
#[cfg(all(feature = "linux", feature = "dlmalloc"))]
mod tests {

    use std::sync::Mutex;

    use asan::{
        allocator::backend::{AllocatorBackend, dlmalloc::DlmallocBackend},
        mmap::linux::LinuxMmap,
    };
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
        let mut allocator = allocator();
        let buf = allocator.alloc(16, 8).unwrap();
        allocator.dealloc(buf, 16, 8).unwrap();
    }
}
