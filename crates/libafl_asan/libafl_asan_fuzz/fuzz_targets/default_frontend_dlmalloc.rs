#![no_main]

use std::sync::{LazyLock, Mutex, MutexGuard};

use libafl_asan::{
    GuestAddr,
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
use libfuzzer_sys::fuzz_target;
use log::info;

type DF = DefaultFrontend<
    DlmallocBackend<LinuxMmap>,
    GuestShadow<LinuxMmap, DefaultShadowLayout>,
    GuestTracking,
>;

const PAGE_SIZE: usize = 4096;

static INIT_ONCE: LazyLock<Mutex<DF>> = LazyLock::new(|| {
    env_logger::init();
    let backend = DlmallocBackend::<LinuxMmap>::new(PAGE_SIZE);
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

const MAX_LENGTH: usize = 0x3ff;
/*
 * Increase the changes of requesting unaligned or minimally aliugned allocations
 * since these are likely to be most common
 */
const ALIGNMENTS: [usize; 16] = [0, 0, 0, 0, 0, 8, 8, 8, 8, 16, 32, 64, 128, 256, 512, 1024];
const ALIGNMENTS_MASK: usize = ALIGNMENTS.len() - 1;

fuzz_target!(|data: Vec<GuestAddr>| {
    if data.len() < 2 {
        return;
    }
    let mut frontend = get_frontend();

    let len = data[0] & MAX_LENGTH;
    let align_idx = data[1] & ALIGNMENTS_MASK;
    let align = ALIGNMENTS[align_idx];

    info!(
        "data: {:x?}, len: {:#x}, align: {:#x}",
        &data[0..2],
        len,
        align
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
