extern crate alloc;

#[cfg(all(test, feature = "linux", target_os = "linux"))]
mod tests {
    use alloc::alloc::{GlobalAlloc, Layout};

    use libafl_asan::{
        GuestAddr,
        allocator::frontend::{AllocatorFrontend, default::DefaultFrontend},
        mmap::{Mmap, linux::LinuxMmap},
        shadow::{
            Shadow,
            guest::{DefaultShadowLayout, GuestShadow},
        },
        tracking::guest::GuestTracking,
    };
    use log::{debug, info};
    use mockall::mock;
    use spin::{Lazy, Mutex, MutexGuard};

    const MAX_ADDR: GuestAddr = 64 << 20;

    // We can't mock GlobalAlloc since `*mut u8` isn't Send and Sync, so we will
    // create a trivial implementation of it which converts the types and calls this
    // substititue mockable trait instead.
    trait BackendTrait {
        fn do_alloc(&self, layout: Layout) -> GuestAddr;
        fn do_dealloc(&self, addr: GuestAddr, layout: Layout);
    }

    mock! {
        #[derive(Debug)]
        pub Backend {}

        impl BackendTrait for Backend {
            fn do_alloc(&self, layout: Layout) -> GuestAddr;
            fn do_dealloc(&self, addr: GuestAddr, layout: Layout);
        }
    }

    unsafe impl GlobalAlloc for MockBackend {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            self.do_alloc(layout) as *mut u8
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            self.do_dealloc(ptr as GuestAddr, layout)
        }
    }

    static INIT_ONCE: Lazy<Mutex<DF>> = Lazy::new(|| {
        Mutex::new({
            env_logger::init();
            let backend = MockBackend::new();
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

    static MAP: Lazy<LinuxMmap> = Lazy::new(|| LinuxMmap::map(MAX_ADDR).unwrap());

    type DF =
        DefaultFrontend<MockBackend, GuestShadow<LinuxMmap, DefaultShadowLayout>, GuestTracking>;

    fn frontend() -> MutexGuard<'static, DF> {
        INIT_ONCE.lock()
    }

    #[test]
    fn test_allocate_is_poisoned() {
        let mut frontend = frontend();

        let base = MAP.as_slice().as_ptr() as GuestAddr;
        info!("base: {base:#x}");

        let inputs = [[4, 8, 0], [0x3ff, 0, 0]];
        for [len, align, addr] in inputs {
            frontend
                .backend_mut()
                .expect_do_alloc()
                .returning(move |layout| {
                    debug!(
                        "mock - len: {:#x}, align: {:#x}",
                        layout.size(),
                        layout.align()
                    );
                    base + addr
                });
            frontend
                .backend_mut()
                .expect_do_dealloc()
                .returning(|addr, layout| {
                    debug!(
                        "mock - addr: {:#x}, len: {:#x}, align: {:#x}",
                        addr,
                        layout.size(),
                        layout.align()
                    );
                });

            let buf = frontend.alloc(len, align).unwrap();
            info!("buf: {buf:#x}");
            for i in buf - DF::DEFAULT_REDZONE_SIZE..buf + len + DF::DEFAULT_REDZONE_SIZE {
                let expected = i < buf || i >= buf + len;
                let poisoned = frontend.shadow().is_poison(i, 1).unwrap();
                assert_eq!(expected, poisoned);
            }
            frontend.dealloc(buf).unwrap();
        }
    }
}
