#![no_main]

use std::{
    fmt::Debug,
    sync::{LazyLock, Mutex, MutexGuard},
};

use asan::{
    GuestAddr,
    allocator::{
        backend::AllocatorBackend,
        frontend::{AllocatorFrontend, default::DefaultFrontend},
    },
    mmap::{Mmap, linux::LinuxMmap},
    shadow::{
        Shadow,
        guest::{DefaultShadowLayout, GuestShadow},
    },
    tracking::guest::GuestTracking,
};
use libfuzzer_sys::fuzz_target;
use log::{debug, info};
use mockall::mock;
use thiserror::Error;

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

type DF = DefaultFrontend<MockBackend, GuestShadow<LinuxMmap, DefaultShadowLayout>, GuestTracking>;

static MAP: LazyLock<LinuxMmap> = LazyLock::new(|| LinuxMmap::map(MAX_ADDR).unwrap());

static INIT_ONCE: LazyLock<Mutex<DF>> = LazyLock::new(|| {
    env_logger::init();
    let backend = MockBackend::new();
    let shadow = GuestShadow::<LinuxMmap, DefaultShadowLayout>::new().unwrap();
    let tracking = GuestTracking::new().unwrap();
    let frontend = DF::new(
        backend,
        shadow,
        tracking,
        DF::DEFAULT_REDZONE_SIZE,
        DF::DEFAULT_QUARANTINE_SIZE,
    )
    .unwrap();
    Mutex::new(frontend)
});

fn get_frontend() -> MutexGuard<'static, DF> {
    INIT_ONCE.lock().unwrap()
}

const MAX_ADDR: GuestAddr = 64 << 20;
const ADDR_MASK: GuestAddr = MAX_ADDR - 8;
const MAX_LENGTH: usize = 0x3ff;
/*
 * Increase the changes of requesting unaligned or minimally aliugned allocations
 * since these are likely to be most common
 */
const ALIGNMENTS: [usize; 16] = [0, 0, 0, 0, 0, 8, 8, 8, 8, 16, 32, 64, 128, 256, 512, 1024];
const ALIGNMENTS_MASK: usize = ALIGNMENTS.len() - 1;

fuzz_target!(|data: Vec<GuestAddr>| {
    if data.len() < 3 {
        return;
    }
    let mut frontend = get_frontend();

    let len = data[0] & MAX_LENGTH;
    let align_idx = data[1] & ALIGNMENTS_MASK;
    let align = ALIGNMENTS[align_idx];
    let addr = data[2] & ADDR_MASK;

    let base = MAP.as_slice().as_ptr() as GuestAddr;

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

    info!(
        "data: {:x?}, len: 0x{:x}, align: 0x{:x}, addr: 0x{:x}",
        &data[0..2],
        len,
        align,
        addr
    );

    if len == 0 {
        return;
    }

    let buf = frontend.alloc(len, align).unwrap();
    for i in buf - DF::DEFAULT_REDZONE_SIZE..buf + len + DF::DEFAULT_REDZONE_SIZE {
        let expected = i < buf || i >= buf + len;
        let poisoned = frontend.shadow().is_poison(i, 1).unwrap();
        assert_eq!(expected, poisoned);
    }
    frontend.dealloc(buf).unwrap();
});
