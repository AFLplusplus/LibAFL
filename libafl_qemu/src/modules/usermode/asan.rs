#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::needless_pass_by_value)] // default compiler complains about Option<&mut T> otherwise, and this is used extensively.

use core::{fmt, slice};
use std::{
    env,
    fmt::{Debug, Display},
    fs,
    pin::Pin,
    sync::Mutex,
};

use hashbrown::{HashMap, HashSet};
use libafl::{executors::ExitKind, observers::ObserversTuple};
use libafl_bolts::os::unix_signals::Signal;
use libafl_qemu_sys::GuestAddr;
use libc::{
    MAP_ANON, MAP_FAILED, MAP_FIXED, MAP_NORESERVE, MAP_PRIVATE, PROT_READ, PROT_WRITE, c_void,
};
use meminterval::{Interval, IntervalTree};
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::{
    Qemu, QemuParams, Regs,
    emu::EmulatorModules,
    modules::{
        AddressFilter, EmulatorModule, EmulatorModuleTuple,
        calls::FullBacktraceCollector,
        snapshot::SnapshotModule,
        utils::filters::{HasAddressFilter, StdAddressFilter},
    },
    qemu::{Hook, MemAccessInfo, QemuHooks, SyscallHookResult},
    sys::TCGTemp,
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

pub const DEFAULT_REDZONE_SIZE: usize = 128;

#[derive(Debug)]
pub struct AsanModule {
    env: Vec<(String, String)>,
    enabled: bool,
    detect_leaks: bool,
    empty: bool,
    rt: Pin<Box<AsanGiovese>>,
    filter: StdAddressFilter,
}

pub struct AsanGiovese {
    pub alloc_tree: Mutex<IntervalTree<GuestAddr, AllocTreeItem>>,
    pub saved_tree: IntervalTree<GuestAddr, AllocTreeItem>,
    pub error_callback: Option<AsanErrorCallback>,
    pub dirty_shadow: Mutex<HashSet<GuestAddr>>,
    pub saved_shadow: HashMap<GuestAddr, Vec<i8>>,
    pub snapshot_shadow: bool,
    pub target_crash: AsanTargetCrash,
    pub error_found: bool,
}

pub struct AsanModuleBuilder {
    env: Vec<(String, String)>,
    detect_leaks: bool,
    snapshot: bool,
    filter: StdAddressFilter,
    error_callback: Option<AsanErrorCallback>,
    target_crash: AsanTargetCrash,
}

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
    Signal(i32),
}

#[derive(Clone, Debug)]
pub enum AsanTargetCrash {
    Never,
    OnFirstError,
    OnTargetStop,
}

#[derive(Debug, Clone)]
pub struct AllocTreeItem {
    backtrace: Vec<GuestAddr>,
    free_backtrace: Vec<GuestAddr>,
    allocated: bool,
}

type AsanErrorFn = Box<dyn FnMut(&AsanGiovese, Qemu, GuestAddr, AsanError)>;

pub struct AsanErrorCallback(AsanErrorFn);

impl AsanErrorCallback {
    /// Initialize a new [`AsanErrorCallback`]
    #[must_use]
    pub fn new(error_callback: AsanErrorFn) -> Self {
        Self(error_callback)
    }

    /// Special [`AsanErrorCallback`] providing a full report in case of QASAN trigger.
    ///
    /// # Safety
    ///
    /// The `ASan` error report accesses [`FullBacktraceCollector`]
    #[must_use]
    pub unsafe fn report() -> Self {
        Self::new(Box::new(|rt, qemu, pc, err| unsafe {
            asan_report(rt, qemu, pc, &err);
        }))
    }

    pub fn call(
        &mut self,
        asan_giovese: &AsanGiovese,
        qemu: Qemu,
        pc: GuestAddr,
        error: AsanError,
    ) {
        self.0(asan_giovese, qemu, pc, error);
    }
}

impl TryFrom<u32> for QasanAction {
    type Error = num_enum::TryFromPrimitiveError<QasanAction>;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        QasanAction::try_from(u64::from(value))
    }
}

impl Display for AsanError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            AsanError::Read(addr, len) => write!(fmt, "Invalid {len} bytes read at {addr:#x}"),
            AsanError::Write(addr, len) => {
                write!(fmt, "Invalid {len} bytes write at {addr:#x}")
            }
            AsanError::BadFree(addr, interval) => match interval {
                Some(chunk) => write!(fmt, "Bad free at {addr:#x} in the allocated chunk {chunk}",),
                None => write!(fmt, "Bad free at {addr:#x} (wild pointer)"),
            },
            AsanError::MemLeak(interval) => write!(fmt, "Memory leak of chunk {interval}"),
            AsanError::Signal(sig) => write!(fmt, "Signal {sig} received"),
        }
    }
}

impl AllocTreeItem {
    #[must_use]
    pub fn alloc(backtrace: Vec<GuestAddr>) -> Self {
        AllocTreeItem {
            backtrace,
            free_backtrace: vec![],
            allocated: true,
        }
    }

    pub fn free(&mut self, backtrace: Vec<GuestAddr>) {
        self.free_backtrace = backtrace;
        self.allocated = false;
    }
}

impl Debug for AsanGiovese {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AsanGiovese")
            .field("alloc_tree", &self.alloc_tree)
            .field("dirty_shadow", &self.dirty_shadow)
            .finish_non_exhaustive()
    }
}

impl AsanModuleBuilder {
    #[must_use]
    pub fn new(
        env: Vec<(String, String)>,
        detect_leaks: bool,
        snapshot: bool,
        filter: StdAddressFilter,
        error_callback: Option<AsanErrorCallback>,
        target_crash: AsanTargetCrash,
    ) -> Self {
        Self {
            env,
            detect_leaks,
            snapshot,
            filter,
            error_callback,
            target_crash,
        }
    }

    #[must_use]
    pub fn env(self, env: &[(String, String)]) -> Self {
        Self::new(
            env.to_vec(),
            self.detect_leaks,
            self.snapshot,
            self.filter,
            self.error_callback,
            self.target_crash,
        )
    }

    #[must_use]
    pub fn detect_leaks(self, detect_leaks: bool) -> Self {
        Self::new(
            self.env,
            detect_leaks,
            self.snapshot,
            self.filter,
            self.error_callback,
            self.target_crash,
        )
    }

    #[must_use]
    pub fn snapshot(self, snapshot: bool) -> Self {
        Self::new(
            self.env,
            self.detect_leaks,
            snapshot,
            self.filter,
            self.error_callback,
            self.target_crash,
        )
    }

    #[must_use]
    pub fn filter(self, filter: StdAddressFilter) -> Self {
        Self::new(
            self.env,
            self.detect_leaks,
            self.snapshot,
            filter,
            self.error_callback,
            self.target_crash,
        )
    }

    #[must_use]
    pub fn error_callback(self, callback: AsanErrorCallback) -> Self {
        Self::new(
            self.env,
            self.detect_leaks,
            self.snapshot,
            self.filter,
            Some(callback),
            self.target_crash,
        )
    }

    /// Get an ASAN report in case of problem.
    ///
    /// # Safety
    ///
    /// The `ASan` error report accesses [`FullBacktraceCollector`].
    /// Check its safety note for more details.
    #[must_use]
    pub unsafe fn asan_report(self) -> Self {
        Self::new(
            self.env,
            self.detect_leaks,
            self.snapshot,
            self.filter,
            Some(unsafe { AsanErrorCallback::report() }),
            self.target_crash,
        )
    }

    #[must_use]
    pub fn target_crash(self, target_crash: AsanTargetCrash) -> Self {
        Self::new(
            self.env,
            self.detect_leaks,
            self.snapshot,
            self.filter,
            self.error_callback,
            target_crash,
        )
    }

    #[must_use]
    pub fn build(self) -> AsanModule {
        AsanModule::new(
            self.env.as_ref(),
            self.detect_leaks,
            self.snapshot,
            self.filter,
            self.error_callback,
            self.target_crash,
        )
    }
}

impl Default for AsanModuleBuilder {
    fn default() -> Self {
        let env = env::vars()
            .filter(|(k, _v)| k != "LD_LIBRARY_PATH")
            .collect::<Vec<(String, String)>>();
        Self::new(
            env,
            false,
            true,
            StdAddressFilter::default(),
            None,
            AsanTargetCrash::OnFirstError,
        )
    }
}

impl AsanModule {
    #[must_use]
    pub fn builder() -> AsanModuleBuilder {
        AsanModuleBuilder::default()
    }

    #[must_use]
    pub fn new(
        env: &[(String, String)],
        detect_leaks: bool,
        snapshot: bool,
        filter: StdAddressFilter,
        error_callback: Option<AsanErrorCallback>,
        target_crash: AsanTargetCrash,
    ) -> Self {
        let mut rt = AsanGiovese::new();

        rt.set_snapshot_shadow(snapshot);
        if let Some(cb) = error_callback {
            rt.set_error_callback(cb);
        }

        rt.set_target_crash(target_crash);

        Self {
            env: env.to_vec(),
            enabled: true,
            detect_leaks,
            empty: true,
            rt,
            filter,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.filter.allowed(&addr)
    }

    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn alloc(&mut self, pc: GuestAddr, start: GuestAddr, end: GuestAddr) {
        self.rt.allocation(pc, start, end);
    }

    pub fn dealloc(&mut self, qemu: Qemu, pc: GuestAddr, addr: GuestAddr) {
        self.rt.deallocation(qemu, pc, addr);
    }

    #[must_use]
    pub fn is_poisoned(&self, qemu: Qemu, addr: GuestAddr, size: usize) -> bool {
        AsanGiovese::is_invalid_access_n(qemu, addr, size)
    }

    pub fn read<const N: usize>(&mut self, qemu: Qemu, pc: GuestAddr, addr: GuestAddr) {
        if self.enabled() && AsanGiovese::is_invalid_access::<N>(qemu, addr) {
            self.rt.report_or_crash(qemu, pc, AsanError::Read(addr, N));
        }
    }

    pub fn read_n(&mut self, qemu: Qemu, pc: GuestAddr, addr: GuestAddr, size: usize) {
        if self.enabled() && AsanGiovese::is_invalid_access_n(qemu, addr, size) {
            self.rt
                .report_or_crash(qemu, pc, AsanError::Read(addr, size));
        }
    }

    pub fn write<const N: usize>(&mut self, qemu: Qemu, pc: GuestAddr, addr: GuestAddr) {
        if self.enabled() && AsanGiovese::is_invalid_access::<N>(qemu, addr) {
            self.rt.report_or_crash(qemu, pc, AsanError::Write(addr, N));
        }
    }

    pub fn write_n(&mut self, qemu: Qemu, pc: GuestAddr, addr: GuestAddr, size: usize) {
        if self.enabled() && AsanGiovese::is_invalid_access_n(qemu, addr, size) {
            self.rt
                .report_or_crash(qemu, pc, AsanError::Write(addr, size));
        }
    }

    pub fn poison(&mut self, qemu: Qemu, addr: GuestAddr, size: usize, poison: PoisonKind) {
        self.rt.poison(qemu, addr, size, poison.into());
    }

    pub fn unpoison(&mut self, qemu: Qemu, addr: GuestAddr, size: usize) {
        AsanGiovese::unpoison(qemu, addr, size);
    }

    pub fn reset(&mut self, qemu: Qemu) -> AsanRollback {
        self.rt.rollback(qemu, self.detect_leaks)
    }
}

impl AsanGiovese {
    unsafe fn init(self: &mut Pin<Box<Self>>, qemu_hooks: QemuHooks) {
        unsafe {
            assert_ne!(
                libc::mmap(
                    HIGH_SHADOW_ADDR,
                    HIGH_SHADOW_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON,
                    -1,
                    0
                ),
                MAP_FAILED
            );
            assert_ne!(
                libc::mmap(
                    LOW_SHADOW_ADDR,
                    LOW_SHADOW_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON,
                    -1,
                    0
                ),
                MAP_FAILED
            );
            assert_ne!(
                libc::mmap(
                    GAP_SHADOW_ADDR,
                    GAP_SHADOW_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON,
                    -1,
                    0
                ),
                MAP_FAILED
            );

            qemu_hooks.add_pre_syscall_hook(self.as_mut(), Self::fake_syscall);
        }
    }

    #[must_use]
    fn new() -> Pin<Box<Self>> {
        let res = Self {
            alloc_tree: Mutex::new(IntervalTree::new()),
            saved_tree: IntervalTree::new(),
            error_callback: None,
            dirty_shadow: Mutex::new(HashSet::default()),
            saved_shadow: HashMap::default(),
            snapshot_shadow: true, // By default, track the dirty shadow pages
            target_crash: AsanTargetCrash::OnFirstError,
            error_found: false,
        };
        Box::pin(res)
    }

    extern "C" fn fake_syscall(
        mut self: Pin<&mut Self>,
        sys_num: i32,
        a0: GuestAddr,
        a1: GuestAddr,
        a2: GuestAddr,
        a3: GuestAddr,
        _a4: GuestAddr,
        _a5: GuestAddr,
        _a6: GuestAddr,
        _a7: GuestAddr,
    ) -> SyscallHookResult {
        if sys_num == QASAN_FAKESYS_NR {
            let mut r = 0;
            let qemu = Qemu::get().unwrap();
            match QasanAction::try_from(a0).expect("Invalid QASan action number") {
                QasanAction::Poison => {
                    self.poison(
                        qemu,
                        a1,
                        a2 as usize,
                        PoisonKind::try_from(a3 as i8).unwrap().into(),
                    );
                }
                QasanAction::UserPoison => {
                    self.poison(qemu, a1, a2 as usize, PoisonKind::User.into());
                }
                QasanAction::UnPoison => {
                    Self::unpoison(qemu, a1, a2 as usize);
                }
                QasanAction::IsPoison => {
                    if Self::is_invalid_access_n(qemu, a1, a2 as usize) {
                        r = 1;
                    }
                }
                QasanAction::Alloc => {
                    let pc: GuestAddr = qemu.read_reg(Regs::Pc).unwrap();
                    self.allocation(pc, a1, a2);
                }
                QasanAction::Dealloc => {
                    let pc: GuestAddr = qemu.read_reg(Regs::Pc).unwrap();
                    self.deallocation(qemu, pc, a1);
                }
                _ => (),
            }
            SyscallHookResult::new(Some(r))
        } else {
            SyscallHookResult::new(None)
        }
    }

    fn set_error_callback(&mut self, error_callback: AsanErrorCallback) {
        self.error_callback = Some(error_callback);
    }

    fn set_snapshot_shadow(&mut self, snapshot_shadow: bool) {
        self.snapshot_shadow = snapshot_shadow;
    }

    fn set_target_crash(&mut self, target_crash: AsanTargetCrash) {
        self.target_crash = target_crash;
    }

    #[inline]
    #[must_use]
    pub fn is_invalid_access<const N: usize>(qemu: Qemu, addr: GuestAddr) -> bool {
        const { assert!(N == 1 || N == 2 || N == 4 || N == 8) };

        unsafe {
            let h = qemu.g2h::<*const c_void>(addr) as isize;
            let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
            if N < 8 {
                let k = *shadow_addr as isize;
                k != 0 && (h & 7).wrapping_add(N as isize) > k
            } else {
                *shadow_addr != 0
            }
        }
    }

    #[inline]
    #[must_use]
    #[expect(clippy::cast_sign_loss)]
    pub fn is_invalid_access_n(qemu: Qemu, addr: GuestAddr, n: usize) -> bool {
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
                    let h = qemu.g2h::<*const c_void>(start) as isize;
                    let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
                    let k = *shadow_addr as isize;
                    return k != 0 && (h & 7).wrapping_add(n) > k;
                }
                let h = qemu.g2h::<*const c_void>(start) as isize;
                let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
                let k = *shadow_addr as isize;
                if k != 0 && (h & 7).wrapping_add(first_size) > k {
                    return true;
                }
                start = next_8;
            }

            while start < last_8 {
                let h = qemu.g2h::<*const c_void>(start) as isize;
                let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
                if *shadow_addr != 0 {
                    return true;
                }
                start = (start).wrapping_add(8);
            }

            if last_8 != end {
                let h = qemu.g2h::<*const c_void>(start) as isize;
                let last_size = end.wrapping_sub(last_8) as isize;
                let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
                let k = *shadow_addr as isize;
                return k != 0 && (h & 7).wrapping_add(last_size) > k;
            }

            false
        }
    }

    #[inline]
    #[expect(clippy::cast_sign_loss)]
    pub fn poison(&mut self, qemu: Qemu, addr: GuestAddr, n: usize, poison_byte: i8) -> bool {
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
                let h = qemu.g2h::<*const c_void>(start) as isize;
                let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
                *shadow_addr = (8isize).wrapping_sub(first_size) as i8;
                start = next_8;
            }

            while start < last_8 {
                let h = qemu.g2h::<*const c_void>(start) as isize;
                let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
                *shadow_addr = poison_byte;
                start = (start).wrapping_add(8);
            }

            true
        }
    }

    #[inline]
    #[expect(clippy::must_use_candidate)]
    #[expect(clippy::cast_sign_loss)]
    pub fn unpoison(qemu: Qemu, addr: GuestAddr, n: usize) -> bool {
        unsafe {
            let n = n as isize;
            let mut start = addr;
            let end = start.wrapping_add(n as GuestAddr);

            while start < end {
                let h = qemu.g2h::<*const c_void>(start) as isize;
                let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
                *shadow_addr = 0;
                start = (start).wrapping_add(8);
            }
            true
        }
    }

    #[inline]
    pub fn unpoison_page(qemu: Qemu, page: GuestAddr) {
        unsafe {
            let h = qemu.g2h::<*const c_void>(page) as isize;
            let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
            shadow_addr.write_bytes(0, SHADOW_PAGE_SIZE);
        }
    }

    #[inline]
    #[expect(clippy::mut_from_ref)]
    fn get_shadow_page(qemu: &Qemu, page: GuestAddr) -> &mut [i8] {
        unsafe {
            let h = qemu.g2h::<*const c_void>(page) as isize;
            let shadow_addr = ((h >> 3) as *mut i8).offset(SHADOW_OFFSET);
            slice::from_raw_parts_mut(shadow_addr, SHADOW_PAGE_SIZE)
        }
    }

    pub fn report_or_crash(&mut self, qemu: Qemu, pc: GuestAddr, error: AsanError) {
        if let Some(mut cb) = self.error_callback.take() {
            cb.call(self, qemu, pc, error);
            self.error_callback = Some(cb);
        }

        if let AsanTargetCrash::OnFirstError = self.target_crash {
            unsafe {
                qemu.target_signal(Signal::SigSegmentationFault);
            }
        }
    }

    pub fn report(&mut self, qemu: Qemu, pc: GuestAddr, error: AsanError) {
        if let Some(mut cb) = self.error_callback.take() {
            cb.call(self, qemu, pc, error);
            self.error_callback = Some(cb);
        }
    }

    pub fn alloc_insert(&mut self, pc: GuestAddr, start: GuestAddr, end: GuestAddr) {
        // # Safety
        // Will access the global [`FullBacktraceCollector`].
        // Calling this function concurrently might be racey.
        let backtrace = FullBacktraceCollector::backtrace()
            .map(|r| {
                let mut v = r.to_vec();
                v.push(pc);
                v
            })
            .unwrap_or_default();
        self.alloc_tree
            .lock()
            .unwrap()
            .insert(start..end, AllocTreeItem::alloc(backtrace));
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

    pub fn alloc_free(&mut self, qemu: Qemu, pc: GuestAddr, addr: GuestAddr) {
        // # Safety
        // Will access the global [`FullBacktraceCollector`].
        // Calling this function concurrently might be racey.
        let mut chunk = None;
        self.alloc_map_mut(addr, |interval, item| {
            chunk = Some(*interval);
            let backtrace = FullBacktraceCollector::backtrace()
                .map(|r| {
                    let mut v = r.to_vec();
                    v.push(pc);
                    v
                })
                .unwrap_or_default();
            item.free(backtrace);
        });
        if let Some(ck) = chunk {
            if ck.start != addr {
                // Free not the start of the chunk
                self.report_or_crash(qemu, pc, AsanError::BadFree(addr, Some(ck)));
            }
        } else {
            // Free of wild ptr
            self.report_or_crash(qemu, pc, AsanError::BadFree(addr, None));
        }
    }

    #[must_use]
    pub fn alloc_get_clone(
        &self,
        query: GuestAddr,
    ) -> Option<(Interval<GuestAddr>, AllocTreeItem)> {
        self.alloc_tree
            .lock()
            .unwrap()
            .query(query..=query)
            .next()
            .map(|entry| (*entry.interval, entry.value.clone()))
    }

    #[must_use]
    pub fn alloc_get_interval(&self, query: GuestAddr) -> Option<Interval<GuestAddr>> {
        self.alloc_tree
            .lock()
            .unwrap()
            .query(query..=query)
            .next()
            .map(|entry| *entry.interval)
    }

    pub fn alloc_map<F>(&self, query: GuestAddr, mut func: F)
    where
        F: FnMut(&Interval<GuestAddr>, &AllocTreeItem),
    {
        if let Some(entry) = self.alloc_tree.lock().unwrap().query(query..=query).next() {
            func(entry.interval, entry.value);
        }
    }

    pub fn alloc_map_mut<F>(&mut self, query: GuestAddr, mut func: F)
    where
        F: FnMut(&Interval<GuestAddr>, &mut AllocTreeItem),
    {
        if let Some(entry) = self
            .alloc_tree
            .lock()
            .unwrap()
            .query_mut(query..=query)
            .next()
        {
            func(entry.interval, entry.value);
        }
    }

    pub fn alloc_map_interval<F>(&self, query: Interval<GuestAddr>, mut func: F)
    where
        F: FnMut(&Interval<GuestAddr>, &AllocTreeItem),
    {
        if let Some(entry) = self.alloc_tree.lock().unwrap().query(query).next() {
            func(entry.interval, entry.value);
        }
    }

    pub fn alloc_map_interval_mut<F>(&mut self, query: Interval<GuestAddr>, mut func: F)
    where
        F: FnMut(&Interval<GuestAddr>, &mut AllocTreeItem),
    {
        if let Some(entry) = self.alloc_tree.lock().unwrap().query_mut(query).next() {
            func(entry.interval, entry.value);
        }
    }

    pub fn allocation(&mut self, pc: GuestAddr, start: GuestAddr, end: GuestAddr) {
        self.alloc_remove(start, end);
        self.alloc_insert(pc, start, end);
    }

    pub fn deallocation(&mut self, qemu: Qemu, pc: GuestAddr, addr: GuestAddr) {
        self.alloc_free(qemu, pc, addr);
    }

    pub fn snapshot(&mut self, qemu: Qemu) {
        if self.snapshot_shadow {
            let set = self.dirty_shadow.lock().unwrap();

            for &page in &*set {
                let data = Self::get_shadow_page(&qemu, page).to_vec();
                self.saved_shadow.insert(page, data);
            }

            let tree = self.alloc_tree.lock().unwrap();
            self.saved_tree = tree.clone();
        }
    }

    pub fn rollback(&mut self, qemu: Qemu, detect_leaks: bool) -> AsanRollback {
        let mut leaks = vec![];

        {
            let mut tree = self.alloc_tree.lock().unwrap();

            if detect_leaks {
                for entry in tree.query(0..GuestAddr::MAX) {
                    leaks.push(*entry.interval);
                }
            }

            if self.snapshot_shadow {
                *tree = self.saved_tree.clone();
            }
        }

        if self.snapshot_shadow {
            let mut set = self.dirty_shadow.lock().unwrap();

            for &page in &*set {
                let original = self.saved_shadow.get(&page);
                if let Some(data) = original {
                    let cur = Self::get_shadow_page(&qemu, page);
                    cur.copy_from_slice(data);
                } else {
                    Self::unpoison_page(qemu, page);
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
            self.report(
                qemu,
                qemu.read_reg(Regs::Pc).unwrap(),
                AsanError::MemLeak(interval),
            );
        }

        ret
    }
}

impl<I, S> EmulatorModule<I, S> for AsanModule
where
    I: Unpin,
    S: Unpin,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = false;

    fn pre_qemu_init<ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        qemu_params: &mut QemuParams,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        let mut args: Vec<String> = qemu_params.to_cli();

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

        // TODO: adapt since qemu does not take envp anymore as parameter
        let mut added = false;
        for (k, v) in &mut self.env {
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
            AsanGiovese::init(&mut self.rt, emulator_modules.hooks().qemu_hooks());
        }

        *qemu_params = QemuParams::Cli(args);
    }

    fn post_qemu_init<ET>(&mut self, _qemu: Qemu, emulator_modules: &mut EmulatorModules<ET, I, S>)
    where
        ET: EmulatorModuleTuple<I, S>,
    {
        emulator_modules.pre_syscalls(Hook::Function(qasan_fake_syscall::<ET, I, S>));

        if self.rt.error_callback.is_some() {
            emulator_modules.crash_function(oncrash_asan::<ET, I, S>);
        }
    }

    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        emulator_modules.reads(
            Hook::Function(gen_readwrite_asan::<ET, I, S>),
            Hook::Function(trace_read_asan::<ET, I, S, 1>),
            Hook::Function(trace_read_asan::<ET, I, S, 2>),
            Hook::Function(trace_read_asan::<ET, I, S, 4>),
            Hook::Function(trace_read_asan::<ET, I, S, 8>),
            Hook::Function(trace_read_n_asan::<ET, I, S>),
        );

        if emulator_modules.get::<SnapshotModule>().is_none() {
            emulator_modules.writes(
                Hook::Function(gen_readwrite_asan::<ET, I, S>),
                Hook::Function(trace_write_asan::<ET, I, S, 1>),
                Hook::Function(trace_write_asan::<ET, I, S, 2>),
                Hook::Function(trace_write_asan::<ET, I, S, 4>),
                Hook::Function(trace_write_asan::<ET, I, S, 8>),
                Hook::Function(trace_write_n_asan::<ET, I, S>),
            );
        } else {
            // track writes for both modules as opt
            emulator_modules.writes(
                Hook::Function(gen_write_asan_snapshot::<ET, I, S>),
                Hook::Function(trace_write_asan_snapshot::<ET, I, S, 1>),
                Hook::Function(trace_write_asan_snapshot::<ET, I, S, 2>),
                Hook::Function(trace_write_asan_snapshot::<ET, I, S, 4>),
                Hook::Function(trace_write_asan_snapshot::<ET, I, S, 8>),
                Hook::Function(trace_write_n_asan_snapshot::<ET, I, S>),
            );
        }
    }

    fn pre_exec<ET>(
        &mut self,
        qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        self.rt.error_found = false;

        if self.empty {
            self.rt.snapshot(qemu);
            self.empty = false;
        }
    }

    fn post_exec<OT, ET>(
        &mut self,
        qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
        _observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        ET: EmulatorModuleTuple<I, S>,
        OT: ObserversTuple<I, S>,
    {
        if let AsanTargetCrash::OnTargetStop = self.rt.target_crash {
            unsafe {
                qemu.target_signal(Signal::SigSegmentationFault);
            }
        }

        if self.reset(qemu) == AsanRollback::HasLeaks {
            *exit_kind = ExitKind::Crash;
        }
    }
}

impl HasAddressFilter for AsanModule {
    type AddressFilter = StdAddressFilter;
    fn address_filter(&self) -> &Self::AddressFilter {
        &self.filter
    }

    fn address_filter_mut(&mut self) -> &mut Self::AddressFilter {
        &mut self.filter
    }
}

pub fn oncrash_asan<ET, I, S>(
    qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    target_sig: i32,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    let h = emulator_modules.get_mut::<AsanModule>().unwrap();
    let pc: GuestAddr = qemu.read_reg(Regs::Pc).unwrap();
    h.rt.report(qemu, pc, AsanError::Signal(target_sig));
}

pub fn gen_readwrite_asan<ET, I, S>(
    _qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
    _addr: *mut TCGTemp,
    _info: MemAccessInfo,
) -> Option<u64>
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    let h = emulator_modules.get_mut::<AsanModule>().unwrap();
    if h.must_instrument(pc) {
        Some(pc.into())
    } else {
        None
    }
}

pub fn trace_read_asan<ET, I, S, const N: usize>(
    qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    id: u64,
    _pc: GuestAddr,
    addr: GuestAddr,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    let h = emulator_modules.get_mut::<AsanModule>().unwrap();
    h.read::<N>(qemu, id as GuestAddr, addr);
}

pub fn trace_read_n_asan<ET, I, S>(
    qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    id: u64,
    _pc: GuestAddr,
    addr: GuestAddr,
    size: usize,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    let h = emulator_modules.get_mut::<AsanModule>().unwrap();
    h.read_n(qemu, id as GuestAddr, addr, size);
}

pub fn trace_write_asan<ET, I, S, const N: usize>(
    qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    id: u64,
    _pc: GuestAddr,
    addr: GuestAddr,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    let h = emulator_modules.get_mut::<AsanModule>().unwrap();
    h.write::<N>(qemu, id as GuestAddr, addr);
}

pub fn trace_write_n_asan<ET, I, S>(
    qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    id: u64,
    _pc: GuestAddr,
    addr: GuestAddr,
    size: usize,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    let h = emulator_modules.get_mut::<AsanModule>().unwrap();
    h.read_n(qemu, id as GuestAddr, addr, size);
}

pub fn gen_write_asan_snapshot<ET, I, S>(
    _qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
    _addr: *mut TCGTemp,
    _info: MemAccessInfo,
) -> Option<u64>
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    let h = emulator_modules.get_mut::<AsanModule>().unwrap();
    if h.must_instrument(pc) {
        Some(pc.into())
    } else {
        Some(0)
    }
}

pub fn trace_write_asan_snapshot<ET, I, S, const N: usize>(
    qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    id: u64,
    _pc: GuestAddr,
    addr: GuestAddr,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    if id != 0 {
        let h = emulator_modules.get_mut::<AsanModule>().unwrap();
        h.write::<N>(qemu, id as GuestAddr, addr);
    }
    let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
    h.access(addr, N);
}

pub fn trace_write_n_asan_snapshot<ET, I, S>(
    qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    id: u64,
    _pc: GuestAddr,
    addr: GuestAddr,
    size: usize,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    if id != 0 {
        let h = emulator_modules.get_mut::<AsanModule>().unwrap();
        h.read_n(qemu, id as GuestAddr, addr, size);
    }
    let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
    h.access(addr, size);
}

#[expect(clippy::too_many_arguments)]
pub fn qasan_fake_syscall<ET, I, S>(
    qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    sys_num: i32,
    a0: GuestAddr,
    a1: GuestAddr,
    a2: GuestAddr,
    _a3: GuestAddr,
    _a4: GuestAddr,
    _a5: GuestAddr,
    _a6: GuestAddr,
    _a7: GuestAddr,
) -> SyscallHookResult
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    if sys_num == QASAN_FAKESYS_NR {
        let h = emulator_modules.get_mut::<AsanModule>().unwrap();
        match QasanAction::try_from(a0).expect("Invalid QASan action number") {
            QasanAction::CheckLoad => {
                let pc: GuestAddr = qemu.read_reg(Regs::Pc).unwrap();
                h.read_n(qemu, pc, a1, a2 as usize);
            }
            QasanAction::CheckStore => {
                let pc: GuestAddr = qemu.read_reg(Regs::Pc).unwrap();
                h.write_n(qemu, pc, a1, a2 as usize);
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
            _ => (),
        }
        SyscallHookResult::new(Some(0))
    } else {
        SyscallHookResult::new(None)
    }
}

/// # Safety
/// Will access the global [`FullBacktraceCollector`].
/// Calling this function concurrently might be racey.
pub unsafe fn asan_report(rt: &AsanGiovese, qemu: Qemu, pc: GuestAddr, err: &AsanError) {
    let resolver = crate::modules::utils::addr2line::AddressResolver::new(&qemu);
    eprintln!("=================================================================");
    let backtrace = FullBacktraceCollector::backtrace()
        .map(|r| {
            let mut v = r.to_vec();
            v.push(pc);
            v
        })
        .unwrap_or(vec![pc]);
    eprintln!("AddressSanitizer Error: {err}");
    for (i, addr) in backtrace.iter().rev().enumerate() {
        eprintln!("\t#{i} {addr:#x}{}", resolver.resolve(*addr));
    }
    let addr = match err {
        AsanError::Read(addr, _) | AsanError::Write(addr, _) | AsanError::BadFree(addr, _) => {
            Some(*addr)
        }
        AsanError::MemLeak(_) | AsanError::Signal(_) => None,
    };
    if let Some(addr) = addr {
        let print_bts = |item: &AllocTreeItem| {
            if item.allocated {
                eprintln!("Allocated at:");
            } else {
                eprintln!("Freed at:");
                for (i, addr) in item.free_backtrace.iter().rev().enumerate() {
                    eprintln!("\t#{i} {addr:#x}{}", resolver.resolve(*addr));
                }
                eprintln!("And previously allocated at:");
            }

            for (i, addr) in item.backtrace.iter().rev().enumerate() {
                eprintln!("\t#{i} {addr:#x}{}", resolver.resolve(*addr));
            }
        };

        if let Some((chunk, item)) = rt.alloc_get_clone(addr) {
            eprintln!(
                "Address {addr:#x} is {} bytes inside the {}-byte chunk [{:#x},{:#x})",
                addr - chunk.start,
                chunk.end - chunk.start,
                chunk.start,
                chunk.end
            );
            print_bts(&item);
        } else {
            let mut found = false;
            rt.alloc_map_interval(
                (addr..=(addr + DEFAULT_REDZONE_SIZE as GuestAddr)).into(),
                |chunk, item| {
                    if found {
                        return;
                    }
                    found = true;
                    eprintln!(
                        "Address {addr:#x} is {} bytes to the left of the {}-byte chunk [{:#x},{:#x})",
                        chunk.start - addr,
                        chunk.end - chunk.start,
                        chunk.start,
                        chunk.end
                    );
                    print_bts(item);
                },
            );
            found = false;
            rt.alloc_map_interval(
                ((addr - DEFAULT_REDZONE_SIZE as GuestAddr)..addr).into(),
                |chunk, item| {
                    if found {
                        return;
                    }
                    found = true;
                    eprintln!(
                        "Address {addr:#x} is {} bytes to the right of the {}-byte chunk [{:#x},{:#x})",
                        addr - chunk.end,
                        chunk.end - chunk.start,
                        chunk.start,
                        chunk.end
                    );
                    print_bts(item);
                },
            );
        }
    }

    // fix pc in case it is not synced (in hooks)
    qemu.write_reg(Regs::Pc, pc).unwrap();
    eprint!(
        "Context:\n{}",
        qemu.current_cpu().unwrap().display_context()
    );
}
