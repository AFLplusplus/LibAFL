#[cfg(test)]
#[cfg(all(feature = "linux"))]
mod tests {

    use asan::{
        allocator::{
            backend::AllocatorBackend,
            frontend::{default::DefaultFrontend, AllocatorFrontend},
        },
        mmap::{linux::LinuxMmap, Mmap},
        shadow::{
            guest::{DefaultShadowLayout, GuestShadow},
            Shadow,
        },
        tracking::guest::GuestTracking,
        GuestAddr,
    };
    use log::{debug, info};
    use mockall::mock;
    use spin::{Lazy, Mutex, MutexGuard};
    use thiserror::Error;

    const MAX_ADDR: GuestAddr = 64 << 20;

    mock! {
        #[derive(Debug)]
        pub Backend {}

        impl AllocatorBackend for Backend {
            type Error = MockBackendError;
            fn alloc(&mut self, len: usize, align: usize) -> Result<GuestAddr, MockBackendError>;
            fn dealloc(&mut self, addr: GuestAddr, len: usize, align: usize) -> Result<(), MockBackendError>;
        }
    }

    #[derive(Error, Debug, PartialEq)]
    pub enum MockBackendError {}

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
        info!("base: 0x{:x}", base);

        let inputs = [[4, 8, 0], [0x3ff, 0, 0]];
        for [len, align, addr] in inputs {
            frontend
                .backend_mut()
                .expect_alloc()
                .returning(move |len, align| {
                    debug!("mock - len: 0x{:x}, align: 0x{:x}", len, align);
                    Ok(base + addr)
                });
            frontend
                .backend_mut()
                .expect_dealloc()
                .returning(|addr, len, align| {
                    debug!(
                        "mock - addr: 0x{:x}, len: 0x{:x}, align: 0x{:x}",
                        addr, len, align
                    );
                    Ok(())
                });

            let buf = frontend.alloc(len, align).unwrap();
            info!("buf: 0x{:x}", buf);
            for i in buf - DF::DEFAULT_REDZONE_SIZE..buf + len + DF::DEFAULT_REDZONE_SIZE {
                let expected = i < buf || i >= buf + len;
                let poisoned = frontend.shadow().is_poison(i, 1).unwrap();
                assert_eq!(expected, poisoned);
            }
            frontend.dealloc(buf).unwrap();
        }
    }
}
