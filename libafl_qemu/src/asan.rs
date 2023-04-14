#![allow(clippy::cast_possible_wrap)]

use std::{
    collections::{HashMap, HashSet},
    env, fs,
    sync::Mutex,
};

use libafl::{
    executors::ExitKind, inputs::UsesInput, observers::ObserversTuple, state::HasMetadata,
};
use libc::{
    c_void, MAP_ANON, MAP_FAILED, MAP_FIXED, MAP_NORESERVE, MAP_PRIVATE, PROT_READ, PROT_WRITE,
};
use meminterval::{Interval, IntervalTree};
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::{
    emu::{EmuError, Emulator, MemAccessInfo, SyscallHookResult},
    helper::{QemuHelper, QemuHelperTuple, QemuInstrumentationFilter},
    hooks::QemuHooks,
    GuestAddr,
};

// TODO at some point, merge parts with libafl_frida

pub const HIGH_SHADOW_ADDR: *mut c_void = 0x02008fff7000 as *mut c_void;
pub const LOW_SHADOW_ADDR: *mut c_void = 0x00007fff8000 as *mut c_void;
pub const GAP_SHADOW_ADDR: *mut c_void = 0x00008fff7000 as *mut c_void;

pub const HIGH_SHADOW_SIZE: usize = 0xdfff0000fff;
pub const LOW_SHADOW_SIZE: usize = 0xfffefff;
pub const GAP_SHADOW_SIZE: usize = 0x1ffffffffff;

pub const SHADOW_OFFSET: isize = 0x7fff8000;

pub const QASAN_FAKESYS_NR: i32 = 0xa2a4;

pub const SHADOW_PAGE_SIZE: usize = 4096;
pub const SHADOW_PAGE_MASK: GuestAddr = !(SHADOW_PAGE_SIZE as GuestAddr - 1);

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy)]
#[repr(u64)]
pub enum QasanAction {
    CheckLoad,
    CheckStore,
    Poison,
    UserPoison,
    UnPoison,
    IsPoison,
    Alloc,
    Dealloc,
    Enable,
    Disable,
    SwapState,
}

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, PartialEq)]
#[repr(i8)]
pub enum PoisonKind {
    Valid = 0,
    Partial1 = 1,
    Partial2 = 2,
    Partial3 = 3,
    Partial4 = 4,
    Partial5 = 5,
    Partial6 = 6,
    Partial7 = 7,
    ArrayCookie = -84,  // 0xac
    StackRz = -16,      // 0xf0
    StackLeftRz = -15,  // 0xf1
    StackMidRz = -14,   // 0xf2
    StackRightRz = -13, // 0xf3
    StacKFreed = -11,   // 0xf5
    StackOOScope = -8,  // 0xf8
    GlobalRz = -7,      // 0xf9
    HeapRz = -23,       // 0xe9
    User = -9,          // 0xf7
    HeapLeftRz = -6,    // 0xfa
    HeapRightRz = -5,   // 0xfb
    HeapFreed = -3,     // 0xfd
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AsanRollback {
    Ok,
    HasLeaks,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AsanError {
    Read(GuestAddr, usize),
    Write(GuestAddr, usize),
    BadFree(GuestAddr, Option<Interval<GuestAddr>>),
    MemLeak(Interval<GuestAddr>),
}

pub type AsanErrorCallback = Box<dyn FnMut(&Emulator, AsanError)>;

pub struct AsanGiovese {
    pub alloc_tree: Mutex<IntervalTree<GuestAddr, ()>>,
    pub saved_tree: IntervalTree<GuestAddr, ()>,
    pub error_callback: Option<AsanErrorCallback>,
    pub dirty_shadow: Mutex<HashSet<GuestAddr>>,
    pub saved_shadow: HashMap<GuestAddr, Vec<i8>>,
    pub snapshot_shadow: bool,
}

impl core::fmt::Debug for AsanGiovese {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AsanGiovese")
            .field("alloc_tree", &self.alloc_tree)
            .field("dirty_shadow", &self.dirty_shadow)
            .finish()
    }
}

impl AsanGiovese {
    pub unsafe fn map_shadow() {
        assert!(
            libc::mmap(
                HIGH_SHADOW_ADDR,
                HIGH_SHADOW_SIZE,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON,
                -1,
                0
            ) != MAP_FAILED
        );
        assert!(
            libc::mmap(
                LOW_SHADOW_ADDR,
                LOW_SHADOW_SIZE,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON,
                -1,
                0
            ) != MAP_FAILED
        );
        assert!(
            libc::mmap(
                GAP_SHADOW_ADDR,
                GAP_SHADOW_SIZE,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON,
                -1,
                0
            ) != MAP_FAILED
        );
    }

    #[inline]
    #[must_use]
    pub fn is_invalid_access_1(emu: &Emulator, addr: GuestAddr) -> bool {
        unsafe {
            let h = emu.g2h::<*const c_void>(addr) as isize;
            let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
            let k = *shadow_addr as isize;
            k != 0 && (h & 7).wrapping_add(1) > k
        }
    }

    #[inline]
    #[must_use]
    pub fn is_invalid_access_2(emu: &Emulator, addr: GuestAddr) -> bool {
        unsafe {
            let h = emu.g2h::<*const c_void>(addr) as isize;
            let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
            let k = *shadow_addr as isize;
            k != 0 && (h & 7).wrapping_add(2) > k
        }
    }

    #[inline]
    #[must_use]
    pub fn is_invalid_access_4(emu: &Emulator, addr: GuestAddr) -> bool {
        unsafe {
            let h = emu.g2h::<*const c_void>(addr) as isize;
            let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
            let k = *shadow_addr as isize;
            k != 0 && (h & 7).wrapping_add(4) > k
        }
    }

    #[inline]
    #[must_use]
    pub fn is_invalid_access_8(emu: &Emulator, addr: GuestAddr) -> bool {
        unsafe {
            let h = emu.g2h::<*const c_void>(addr) as isize;
            let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
            *shadow_addr != 0
        }
    }

    #[inline]
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub fn is_invalid_access(emu: &Emulator, addr: GuestAddr, n: usize) -> bool {
        unsafe {
            if n == 0 {
                return false;
            }

            let n = n as isize;
            let mut start = addr;
            let end = start.wrapping_add(n as GuestAddr);
            let last_8 = end & !7;

            if start & 0x7 != 0 {
                let next_8 = (start & !7).wrapping_add(8);
                let first_size = next_8.wrapping_sub(start) as isize;
                if n <= first_size {
                    let h = emu.g2h::<*const c_void>(start) as isize;
                    let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
                    let k = *shadow_addr as isize;
                    return k != 0 && (h & 7).wrapping_add(n) > k;
                }
                let h = emu.g2h::<*const c_void>(start) as isize;
                let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
                let k = *shadow_addr as isize;
                if k != 0 && (h & 7).wrapping_add(first_size) > k {
                    return true;
                }
                start = next_8;
            }

            while start < last_8 {
                let h = emu.g2h::<*const c_void>(start) as isize;
                let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
                if *shadow_addr != 0 {
                    return true;
                }
                start = (start).wrapping_add(8);
            }

            if last_8 != end {
                let h = emu.g2h::<*const c_void>(start) as isize;
                let last_size = end.wrapping_sub(last_8) as isize;
                let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
                let k = *shadow_addr as isize;
                return k != 0 && (h & 7).wrapping_add(last_size) > k;
            }

            false
        }
    }

    #[inline]
    #[allow(clippy::cast_sign_loss)]
    pub fn poison(&mut self, emu: &Emulator, addr: GuestAddr, n: usize, poison_byte: i8) -> bool {
        unsafe {
            if n == 0 {
                return false;
            }

            if self.snapshot_shadow {
                let mut page = addr & SHADOW_PAGE_MASK;
                let mut set = self.dirty_shadow.lock().unwrap();
                while page < addr + n as GuestAddr {
                    set.insert(page);
                    page += SHADOW_PAGE_SIZE as GuestAddr;
                }
            }

            let n = n as isize;
            let mut start = addr;
            let end = start.wrapping_add(n as GuestAddr);
            let last_8 = end & !7;

            if start & 0x7 != 0 {
                let next_8 = (start & !7).wrapping_add(8);
                let first_size = next_8.wrapping_sub(start) as isize;
                if n < first_size {
                    return false;
                }
                let h = emu.g2h::<*const c_void>(start) as isize;
                let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
                *shadow_addr = (8isize).wrapping_sub(first_size) as i8;
                start = next_8;
            }

            while start < last_8 {
                let h = emu.g2h::<*const c_void>(start) as isize;
                let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
                *shadow_addr = poison_byte;
                start = (start).wrapping_add(8);
            }

            true
        }
    }

    #[inline]
    #[allow(clippy::must_use_candidate)]
    #[allow(clippy::cast_sign_loss)]
    pub fn unpoison(emu: &Emulator, addr: GuestAddr, n: usize) -> bool {
        unsafe {
            let n = n as isize;
            let mut start = addr;
            let end = start.wrapping_add(n as GuestAddr);

            while start < end {
                let h = emu.g2h::<*const c_void>(start) as isize;
                let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
                *shadow_addr = 0;
                start = (start).wrapping_add(8);
            }
            true
        }
    }

    #[inline]
    fn unpoison_page(emu: &Emulator, page: GuestAddr) {
        unsafe {
            let h = emu.g2h::<*const c_void>(page) as isize;
            let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
            shadow_addr.write_bytes(0, SHADOW_PAGE_SIZE);
        }
    }

    #[inline]
    #[allow(clippy::mut_from_ref)]
    fn get_shadow_page(emu: &Emulator, page: GuestAddr) -> &mut [i8] {
        unsafe {
            let h = emu.g2h::<*const c_void>(page) as isize;
            let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
            std::slice::from_raw_parts_mut(shadow_addr, SHADOW_PAGE_SIZE)
        }
    }

    #[must_use]
    pub fn new(snapshot_shadow: bool) -> Self {
        Self {
            alloc_tree: Mutex::new(IntervalTree::new()),
            saved_tree: IntervalTree::new(),
            error_callback: None,
            dirty_shadow: Mutex::new(HashSet::default()),
            saved_shadow: HashMap::default(),
            snapshot_shadow,
        }
    }

    #[must_use]
    pub fn with_error_callback(snapshot_shadow: bool, error_callback: AsanErrorCallback) -> Self {
        Self {
            alloc_tree: Mutex::new(IntervalTree::new()),
            saved_tree: IntervalTree::new(),
            error_callback: Some(error_callback),
            dirty_shadow: Mutex::new(HashSet::default()),
            saved_shadow: HashMap::default(),
            snapshot_shadow,
        }
    }

    pub fn report_or_crash(&mut self, emu: &Emulator, error: AsanError) {
        if let Some(cb) = self.error_callback.as_mut() {
            (cb)(emu, error);
        } else {
            std::process::abort();
        }
    }

    pub fn report(&mut self, emu: &Emulator, error: AsanError) {
        if let Some(cb) = self.error_callback.as_mut() {
            (cb)(emu, error);
        }
    }

    pub fn alloc_insert(&mut self, start: GuestAddr, end: GuestAddr) {
        self.alloc_tree.lock().unwrap().insert(start..end, ());
    }

    pub fn alloc_remove(&mut self, start: GuestAddr, end: GuestAddr) {
        let mut tree = self.alloc_tree.lock().unwrap();
        let mut found = vec![];
        for entry in tree.query(start..end) {
            found.push(*entry.interval);
        }
        for interval in found {
            tree.delete(interval);
        }
    }

    #[must_use]
    pub fn alloc_search(&mut self, query: GuestAddr) -> Option<Interval<GuestAddr>> {
        self.alloc_tree
            .lock()
            .unwrap()
            .query(query..=query)
            .next()
            .map(|entry| *entry.interval)
    }

    pub fn snapshot(&mut self, emu: &Emulator) {
        if self.snapshot_shadow {
            let set = self.dirty_shadow.lock().unwrap();

            for &page in set.iter() {
                let data = Self::get_shadow_page(emu, page).to_vec();
                self.saved_shadow.insert(page, data);
            }

            let tree = self.alloc_tree.lock().unwrap();
            self.saved_tree = tree.clone();
        }
    }

    pub fn rollback(&mut self, emu: &Emulator, detect_leaks: bool) -> AsanRollback {
        let mut leaks = vec![];

        {
            let mut tree = self.alloc_tree.lock().unwrap();

            if detect_leaks {
                for entry in tree.query(0..GuestAddr::MAX) {
                    leaks.push(*entry.interval);
                }
            }

            if self.snapshot_shadow {
                tree.clear();
            }
        }

        if self.snapshot_shadow {
            let mut set = self.dirty_shadow.lock().unwrap();

            for &page in set.iter() {
                let original = self.saved_shadow.get(&page);
                if let Some(data) = original {
                    let cur = Self::get_shadow_page(emu, page);
                    cur.copy_from_slice(data);
                } else {
                    Self::unpoison_page(emu, page);
                }
            }

            set.clear();
        }

        let ret = if leaks.is_empty() {
            AsanRollback::Ok
        } else {
            AsanRollback::HasLeaks
        };

        for interval in leaks {
            self.report(emu, AsanError::MemLeak(interval));
        }

        ret
    }
}

static mut ASAN_INITED: bool = false;

pub fn init_with_asan(
    args: &mut Vec<String>,
    env: &mut [(String, String)],
) -> Result<Emulator, EmuError> {
    let current = env::current_exe().unwrap();
    let asan_lib = fs::canonicalize(current)
        .unwrap()
        .parent()
        .unwrap()
        .join("libqasan.so");
    let asan_lib = asan_lib
        .to_str()
        .expect("The path to the asan lib is invalid")
        .to_string();
    let add_asan =
        |e: &str| "LD_PRELOAD=".to_string() + &asan_lib + " " + &e["LD_PRELOAD=".len()..];

    let mut added = false;
    for (k, v) in env.iter_mut() {
        if k == "QEMU_SET_ENV" {
            let mut new_v = vec![];
            for e in v.split(',') {
                if e.starts_with("LD_PRELOAD=") {
                    added = true;
                    new_v.push(add_asan(e));
                } else {
                    new_v.push(e.to_string());
                }
            }
            *v = new_v.join(",");
        }
    }
    for i in 0..args.len() {
        if args[i] == "-E" && i + 1 < args.len() && args[i + 1].starts_with("LD_PRELOAD=") {
            added = true;
            args[i + 1] = add_asan(&args[i + 1]);
        }
    }

    if !added {
        args.insert(1, "LD_PRELOAD=".to_string() + &asan_lib);
        args.insert(1, "-E".into());
    }

    unsafe {
        AsanGiovese::map_shadow();
        ASAN_INITED = true;
    }
    Emulator::new(args, env)
}

pub enum QemuAsanOptions {
    None,
    Snapshot,
    DetectLeaks,
    SnapshotDetectLeaks,
}

pub type QemuAsanChildHelper = QemuAsanHelper;

#[derive(Debug)]
pub struct QemuAsanHelper {
    enabled: bool,
    detect_leaks: bool,
    empty: bool,
    rt: AsanGiovese,
    filter: QemuInstrumentationFilter,
}

impl QemuAsanHelper {
    #[must_use]
    pub fn new(filter: QemuInstrumentationFilter, options: QemuAsanOptions) -> Self {
        assert!(unsafe { ASAN_INITED }, "The ASan runtime is not initialized, use init_with_asan(...) instead of just Emulator::new(...)");
        let (snapshot, detect_leaks) = match options {
            QemuAsanOptions::None => (false, false),
            QemuAsanOptions::Snapshot => (true, false),
            QemuAsanOptions::DetectLeaks => (false, true),
            QemuAsanOptions::SnapshotDetectLeaks => (true, true),
        };
        Self {
            enabled: true,
            detect_leaks,
            empty: true,
            rt: AsanGiovese::new(snapshot),
            filter,
        }
    }

    #[must_use]
    pub fn with_error_callback(
        filter: QemuInstrumentationFilter,
        error_callback: AsanErrorCallback,
        options: QemuAsanOptions,
    ) -> Self {
        assert!(unsafe { ASAN_INITED }, "The ASan runtime is not initialized, use init_with_asan(...) instead of just Emulator::new(...)");
        let (snapshot, detect_leaks) = match options {
            QemuAsanOptions::None => (false, false),
            QemuAsanOptions::Snapshot => (true, false),
            QemuAsanOptions::DetectLeaks => (false, true),
            QemuAsanOptions::SnapshotDetectLeaks => (true, true),
        };
        Self {
            enabled: true,
            detect_leaks,
            empty: true,
            rt: AsanGiovese::with_error_callback(snapshot, error_callback),
            filter,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.filter.allowed(addr)
    }

    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn alloc(&mut self, _emulator: &Emulator, start: GuestAddr, end: GuestAddr) {
        self.rt.alloc_insert(start, end);
    }

    pub fn dealloc(&mut self, emulator: &Emulator, addr: GuestAddr) {
        let chunk = self.rt.alloc_search(addr);
        if let Some(ck) = chunk {
            if ck.start != addr {
                // Free not the start of the chunk
                self.rt
                    .report_or_crash(emulator, AsanError::BadFree(addr, Some(ck)));
            }
        } else {
            // Free of wild ptr
            self.rt
                .report_or_crash(emulator, AsanError::BadFree(addr, None));
        }
    }

    #[allow(clippy::unused_self)]
    #[must_use]
    pub fn is_poisoned(&self, emulator: &Emulator, addr: GuestAddr, size: usize) -> bool {
        AsanGiovese::is_invalid_access(emulator, addr, size)
    }

    pub fn read_1(&mut self, emulator: &Emulator, addr: GuestAddr) {
        if self.enabled() && AsanGiovese::is_invalid_access_1(emulator, addr) {
            self.rt.report_or_crash(emulator, AsanError::Read(addr, 1));
        }
    }

    pub fn read_2(&mut self, emulator: &Emulator, addr: GuestAddr) {
        if self.enabled() && AsanGiovese::is_invalid_access_2(emulator, addr) {
            self.rt.report_or_crash(emulator, AsanError::Read(addr, 2));
        }
    }

    pub fn read_4(&mut self, emulator: &Emulator, addr: GuestAddr) {
        if self.enabled() && AsanGiovese::is_invalid_access_4(emulator, addr) {
            self.rt.report_or_crash(emulator, AsanError::Read(addr, 4));
        }
    }

    pub fn read_8(&mut self, emulator: &Emulator, addr: GuestAddr) {
        if self.enabled() && AsanGiovese::is_invalid_access_8(emulator, addr) {
            self.rt.report_or_crash(emulator, AsanError::Read(addr, 8));
        }
    }

    pub fn read_n(&mut self, emulator: &Emulator, addr: GuestAddr, size: usize) {
        if self.enabled() && AsanGiovese::is_invalid_access(emulator, addr, size) {
            self.rt
                .report_or_crash(emulator, AsanError::Read(addr, size));
        }
    }

    pub fn write_1(&mut self, emulator: &Emulator, addr: GuestAddr) {
        if self.enabled() && AsanGiovese::is_invalid_access_1(emulator, addr) {
            self.rt.report_or_crash(emulator, AsanError::Write(addr, 1));
        }
    }

    pub fn write_2(&mut self, emulator: &Emulator, addr: GuestAddr) {
        if self.enabled() && AsanGiovese::is_invalid_access_2(emulator, addr) {
            self.rt.report_or_crash(emulator, AsanError::Write(addr, 2));
        }
    }

    pub fn write_4(&mut self, emulator: &Emulator, addr: GuestAddr) {
        if self.enabled() && AsanGiovese::is_invalid_access_4(emulator, addr) {
            self.rt.report_or_crash(emulator, AsanError::Write(addr, 4));
        }
    }

    pub fn write_8(&mut self, emulator: &Emulator, addr: GuestAddr) {
        if self.enabled() && AsanGiovese::is_invalid_access_8(emulator, addr) {
            self.rt.report_or_crash(emulator, AsanError::Write(addr, 8));
        }
    }

    pub fn write_n(&mut self, emulator: &Emulator, addr: GuestAddr, size: usize) {
        if self.enabled() && AsanGiovese::is_invalid_access(emulator, addr, size) {
            self.rt
                .report_or_crash(emulator, AsanError::Write(addr, size));
        }
    }

    pub fn poison(
        &mut self,
        emulator: &Emulator,
        addr: GuestAddr,
        size: usize,
        poison: PoisonKind,
    ) {
        self.rt.poison(emulator, addr, size, poison.into());
    }

    #[allow(clippy::unused_self)]
    pub fn unpoison(&mut self, emulator: &Emulator, addr: GuestAddr, size: usize) {
        AsanGiovese::unpoison(emulator, addr, size);
    }

    pub fn reset(&mut self, emulator: &Emulator) -> AsanRollback {
        self.rt.rollback(emulator, self.detect_leaks)
    }
}

impl Default for QemuAsanHelper {
    fn default() -> Self {
        Self::new(QemuInstrumentationFilter::None, QemuAsanOptions::Snapshot)
    }
}

impl<S> QemuHelper<S> for QemuAsanHelper
where
    S: UsesInput + HasMetadata,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = false;

    fn init_hooks<QT>(&self, hooks: &QemuHooks<'_, QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        hooks.syscalls(qasan_fake_syscall::<QT, S>);
    }

    fn first_exec<QT>(&self, hooks: &QemuHooks<'_, QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        hooks.reads(
            Some(gen_readwrite_asan::<QT, S>),
            Some(trace_read1_asan::<QT, S>),
            Some(trace_read2_asan::<QT, S>),
            Some(trace_read4_asan::<QT, S>),
            Some(trace_read8_asan::<QT, S>),
            Some(trace_read_n_asan::<QT, S>),
        );

        hooks.writes(
            Some(gen_readwrite_asan::<QT, S>),
            Some(trace_write1_asan::<QT, S>),
            Some(trace_write2_asan::<QT, S>),
            Some(trace_write4_asan::<QT, S>),
            Some(trace_write8_asan::<QT, S>),
            Some(trace_write_n_asan::<QT, S>),
        );
    }

    fn pre_exec(&mut self, emulator: &Emulator, _input: &S::Input) {
        if self.empty {
            self.rt.snapshot(emulator);
            self.empty = false;
        }
    }

    fn post_exec<OT>(
        &mut self,
        emulator: &Emulator,
        _input: &S::Input,
        _observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
    {
        if self.reset(emulator) == AsanRollback::HasLeaks {
            *exit_kind = ExitKind::Crash;
        }
    }
}

pub fn gen_readwrite_asan<QT, S>(
    hooks: &mut QemuHooks<'_, QT, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
    _info: MemAccessInfo,
) -> Option<u64>
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let h = hooks.match_helper_mut::<QemuAsanHelper>().unwrap();
    if h.must_instrument(pc) {
        Some(pc.into())
    } else {
        None
    }
}

pub fn trace_read1_asan<QT, S>(
    hooks: &mut QemuHooks<'_, QT, S>,
    _state: Option<&mut S>,
    _id: u64,
    addr: GuestAddr,
) where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let emulator = hooks.emulator().clone();
    let h = hooks.match_helper_mut::<QemuAsanHelper>().unwrap();
    h.read_1(&emulator, addr);
}

pub fn trace_read2_asan<QT, S>(
    hooks: &mut QemuHooks<'_, QT, S>,
    _state: Option<&mut S>,
    _id: u64,
    addr: GuestAddr,
) where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let emulator = hooks.emulator().clone();
    let h = hooks.match_helper_mut::<QemuAsanHelper>().unwrap();
    h.read_2(&emulator, addr);
}

pub fn trace_read4_asan<QT, S>(
    hooks: &mut QemuHooks<'_, QT, S>,
    _state: Option<&mut S>,
    _id: u64,
    addr: GuestAddr,
) where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let emulator = hooks.emulator().clone();
    let h = hooks.match_helper_mut::<QemuAsanHelper>().unwrap();
    h.read_4(&emulator, addr);
}

pub fn trace_read8_asan<QT, S>(
    hooks: &mut QemuHooks<'_, QT, S>,
    _state: Option<&mut S>,
    _id: u64,
    addr: GuestAddr,
) where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let emulator = hooks.emulator().clone();
    let h = hooks.match_helper_mut::<QemuAsanHelper>().unwrap();
    h.read_8(&emulator, addr);
}

pub fn trace_read_n_asan<QT, S>(
    hooks: &mut QemuHooks<'_, QT, S>,
    _state: Option<&mut S>,
    _id: u64,
    addr: GuestAddr,
    size: usize,
) where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let emulator = hooks.emulator().clone();
    let h = hooks.match_helper_mut::<QemuAsanHelper>().unwrap();
    h.read_n(&emulator, addr, size);
}

pub fn trace_write1_asan<QT, S>(
    hooks: &mut QemuHooks<'_, QT, S>,
    _state: Option<&mut S>,
    _id: u64,
    addr: GuestAddr,
) where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let emulator = hooks.emulator().clone();
    let h = hooks.match_helper_mut::<QemuAsanHelper>().unwrap();
    h.write_1(&emulator, addr);
}

pub fn trace_write2_asan<QT, S>(
    hooks: &mut QemuHooks<'_, QT, S>,
    _state: Option<&mut S>,
    _id: u64,
    addr: GuestAddr,
) where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let emulator = hooks.emulator().clone();
    let h = hooks.match_helper_mut::<QemuAsanHelper>().unwrap();
    h.write_2(&emulator, addr);
}

pub fn trace_write4_asan<QT, S>(
    hooks: &mut QemuHooks<'_, QT, S>,
    _state: Option<&mut S>,
    _id: u64,
    addr: GuestAddr,
) where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let emulator = hooks.emulator().clone();
    let h = hooks.match_helper_mut::<QemuAsanHelper>().unwrap();
    h.write_4(&emulator, addr);
}

pub fn trace_write8_asan<QT, S>(
    hooks: &mut QemuHooks<'_, QT, S>,
    _state: Option<&mut S>,
    _id: u64,
    addr: GuestAddr,
) where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let emulator = hooks.emulator().clone();
    let h = hooks.match_helper_mut::<QemuAsanHelper>().unwrap();
    h.write_8(&emulator, addr);
}

pub fn trace_write_n_asan<QT, S>(
    hooks: &mut QemuHooks<'_, QT, S>,
    _state: Option<&mut S>,
    _id: u64,
    addr: GuestAddr,
    size: usize,
) where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let emulator = hooks.emulator().clone();
    let h = hooks.match_helper_mut::<QemuAsanHelper>().unwrap();
    h.read_n(&emulator, addr, size);
}

#[allow(clippy::too_many_arguments)]
pub fn qasan_fake_syscall<QT, S>(
    hooks: &mut QemuHooks<'_, QT, S>,
    _state: Option<&mut S>,
    sys_num: i32,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    _a4: u64,
    _a5: u64,
    _a6: u64,
    _a7: u64,
) -> SyscallHookResult
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    if sys_num == QASAN_FAKESYS_NR {
        let emulator = hooks.emulator().clone();
        let h = hooks.match_helper_mut::<QemuAsanHelper>().unwrap();
        let mut r = 0;
        match QasanAction::try_from(a0).expect("Invalid QASan action number") {
            QasanAction::CheckLoad => {
                h.read_n(&emulator, a1 as GuestAddr, a2 as usize);
            }
            QasanAction::CheckStore => {
                h.write_n(&emulator, a1 as GuestAddr, a2 as usize);
            }
            QasanAction::Poison => {
                h.poison(
                    &emulator,
                    a1 as GuestAddr,
                    a2 as usize,
                    PoisonKind::try_from(a3 as i8).unwrap(),
                );
            }
            QasanAction::UserPoison => {
                h.poison(&emulator, a1 as GuestAddr, a2 as usize, PoisonKind::User);
            }
            QasanAction::UnPoison => {
                h.unpoison(&emulator, a1 as GuestAddr, a2 as usize);
            }
            QasanAction::IsPoison => {
                if h.is_poisoned(&emulator, a1 as GuestAddr, a2 as usize) {
                    r = 1;
                }
            }
            QasanAction::Alloc => {
                h.alloc(&emulator, a1 as GuestAddr, a2 as GuestAddr);
            }
            QasanAction::Dealloc => {
                h.dealloc(&emulator, a1 as GuestAddr);
            }
            QasanAction::Enable => {
                h.set_enabled(true);
            }
            QasanAction::Disable => {
                h.set_enabled(false);
            }
            QasanAction::SwapState => {
                h.set_enabled(!h.enabled());
            }
        }
        SyscallHookResult::new(Some(r))
    } else {
        SyscallHookResult::new(None)
    }
}
