#[cfg(all(test, feature = "linux", target_os = "linux", feature = "dlmalloc"))]
mod tests {

    use libafl_asan::{
        allocator::{
            backend::dlmalloc::DlmallocBackend,
            frontend::{AllocatorFrontend, default::DefaultFrontend},
        },
        mmap::linux::LinuxMmap,
        shadow::{
            Shadow,
            guest::{DefaultShadowLayout, GuestShadow},
        },
        tracking::guest::GuestTracking,
    };
    use spin::{Lazy, Mutex, MutexGuard};

    const PAGE_SIZE: usize = 4096;

    static INIT_ONCE: Lazy<Mutex<DF>> = Lazy::new(|| {
        Mutex::new({
            env_logger::init();
            let backend = DlmallocBackend::<LinuxMmap>::new(PAGE_SIZE);
            let shadow = GuestShadow::<LinuxMmap, DefaultShadowLayout>::new().unwrap();
            let tracking = GuestTracking::new().unwrap();
            DF::new(
                backend,
                shadow,
                tracking,
                DF::DEFAULT_REDZONE_SIZE,
                DF::DEFAULT_QUARANTINE_SIZE,
            )
            .unwrap()
        })
    });

    type DF = DefaultFrontend<
        DlmallocBackend<LinuxMmap>,
        GuestShadow<LinuxMmap, DefaultShadowLayout>,
        GuestTracking,
    >;

    fn frontend() -> MutexGuard<'static, DF> {
        INIT_ONCE.lock()
    }

    #[test]
    fn test_allocate() {
        let mut frontend = frontend();
        let buf = frontend.alloc(16, 8).unwrap();
        frontend.dealloc(buf).unwrap();
    }

    #[test]
    fn test_allocate_is_poisoned() {
        let mut frontend = frontend();
        let len = 16;
        let buf = frontend.alloc(len, 8).unwrap();
        for i in buf - DF::DEFAULT_REDZONE_SIZE..buf + len + DF::DEFAULT_REDZONE_SIZE {
            let expected = i < buf || i >= buf + len;
            let poisoned = frontend.shadow().is_poison(i, 1).unwrap();
            assert_eq!(expected, poisoned);
        }
        frontend.dealloc(buf).unwrap();
    }
}
