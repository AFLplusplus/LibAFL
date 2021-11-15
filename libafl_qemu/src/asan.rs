use libafl::{executors::ExitKind, inputs::Input, observers::ObserversTuple, state::HasMetadata};
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::{
    emu,
    emu::SyscallHookResult,
    executor::QemuExecutor,
    helper::{QemuHelper, QemuHelperTuple, QemuInstrumentationFilter},
};

// TODO at some point, merge parts with libafl_frida

pub const QASAN_FAKESYS_NR: i32 = 0xa2a4;

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

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy)]
#[repr(u8)]
pub enum PoisonKind {
    Valid = 0,
    Partial1 = 1,
    Partial2 = 2,
    Partial3 = 3,
    Partial4 = 4,
    Partial5 = 5,
    Partial6 = 6,
    Partial7 = 7,
    ArrayCookie = 0xac,
    StackRz = 0xf0,
    StackLeftRz = 0xf1,
    StackMidRz = 0xf2,
    StackRightRz = 0xf3,
    StacKFreed = 0xf5,
    StackOOScope = 0xf8,
    GlobalRz = 0xf9,
    HeapRz = 0xe9,
    User = 0xf7,
    HeapLeftRz = 0xfa,
    HeapRightRz = 0xfb,
    HeapFreed = 0xfd,
}

#[repr(C)]
struct CallContext {
    pub addresses: *const u64,
    pub tid: u32,
    pub size: u32,
}

#[repr(C)]
struct ChunkInfo {
    pub start: u64,
    pub end: u64,
    pub alloc_ctx: *const CallContext,
    pub free_ctx: *const CallContext, // NULL if chunk is allocated
}

extern "C" {
    // int asan_giovese_loadN(void* ptr, size_t n);
    fn asan_giovese_loadN(ptr: *const u8, n: usize) -> i32;
    // int asan_giovese_storeN(void* ptr, size_t n);
    fn asan_giovese_storeN(ptr: *const u8, n: usize) -> i32;
    // int asan_giovese_poison_region(void* ptr, size_t n, uint8_t poison_byte);
    fn asan_giovese_poison_region(ptr: *const u8, n: usize, poison: u8) -> i32;
    // int asan_giovese_unpoison_region(void* ptr, size_t n);
    fn asan_giovese_unpoison_region(ptr: *const u8, n: usize) -> i32;
    // struct chunk_info* asan_giovese_alloc_search(target_ulong query);
    fn asan_giovese_alloc_search(query: u64) -> *mut ChunkInfo;
    // void asan_giovese_alloc_remove(target_ulong start, target_ulong end);
    fn asan_giovese_alloc_remove(start: u64, end: u64);
    // void asan_giovese_alloc_insert(target_ulong start, target_ulong end, struct call_context* alloc_ctx);
    fn asan_giovese_alloc_insert(start: u64, end: u64, alloc_ctx: *const CallContext);
}

// TODO be thread-safe maybe with https://amanieu.github.io/thread_local-rs/thread_local/index.html
pub struct QemuAsanHelper {
    pub enabled: bool,
}

impl QemuAsanHelper {
    #[must_use]
    pub fn new() -> Self {
        Self { enabled: false }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn alloc(&mut self, start: u64, end: u64) {
        unsafe {
            let ctx: *const CallContext =
                libc::calloc(core::mem::size_of::<CallContext>(), 1) as *const _;
            asan_giovese_alloc_insert(start, end, ctx);
        }
    }

    pub fn dealloc(&mut self, addr: u64) {
        unsafe {
            let ckinfo = asan_giovese_alloc_search(addr);
            if let Some(ck) = ckinfo.as_mut() {
                let ctx: *const CallContext =
                    libc::calloc(core::mem::size_of::<CallContext>(), 1) as *const _;
                ck.free_ctx = ctx;
            }
        }
    }

    pub fn is_poisoned(&mut self, addr: u64, size: usize) -> bool {
        unsafe { asan_giovese_loadN(emu::g2h(addr), size) != 0 }
    }

    pub fn read_n(&mut self, addr: u64, size: usize) {
        if self.enabled() && unsafe { asan_giovese_loadN(emu::g2h(addr), size) != 0 } {
            std::process::abort();
        }
    }

    pub fn write_n(&mut self, addr: u64, size: usize) {
        if self.enabled() && unsafe { asan_giovese_storeN(emu::g2h(addr), size) != 0 } {
            std::process::abort();
        }
    }

    pub fn poison(&mut self, addr: u64, size: usize, poison: PoisonKind) {
        unsafe { asan_giovese_poison_region(emu::g2h(addr), size, poison.into()) };
    }

    pub fn unpoison(&mut self, addr: u64, size: usize) {
        unsafe { asan_giovese_unpoison_region(emu::g2h(addr), size) };
    }

    pub fn reset(&mut self) {
        unsafe { asan_giovese_alloc_remove(0, u64::MAX) };
    }
}

impl Default for QemuAsanHelper {
    fn default() -> Self {
        Self::new()
    }
}

impl<I, S> QemuHelper<I, S> for QemuAsanHelper
where
    I: Input,
    S: HasMetadata,
{
    fn init<'a, H, OT, QT>(&self, executor: &QemuExecutor<'a, H, I, OT, QT, S>)
    where
        H: FnMut(&I) -> ExitKind,
        OT: ObserversTuple<I, S>,
        QT: QemuHelperTuple<I, S>,
    {
        executor.hook_read8_execution(trace_read8_asan::<I, QT, S>);
        executor.hook_read4_execution(trace_read4_asan::<I, QT, S>);
        executor.hook_read2_execution(trace_read2_asan::<I, QT, S>);
        executor.hook_read1_execution(trace_read1_asan::<I, QT, S>);
        executor.hook_read_n_execution(trace_read_n_asan::<I, QT, S>);

        executor.hook_write8_execution(trace_write8_asan::<I, QT, S>);
        executor.hook_write4_execution(trace_write4_asan::<I, QT, S>);
        executor.hook_write2_execution(trace_write2_asan::<I, QT, S>);
        executor.hook_write1_execution(trace_write1_asan::<I, QT, S>);
        executor.hook_write_n_execution(trace_write_n_asan::<I, QT, S>);
    }

    fn post_exec(&mut self, _input: &I) {
        self.reset();
    }
}

pub fn trace_read1_asan<I, QT, S>(helpers: &mut QT, _state: &mut S, _id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let h = helpers.match_first_type_mut::<QemuAsanHelper>().unwrap();
    h.read_n(addr, 1);
}

pub fn trace_read2_asan<I, QT, S>(helpers: &mut QT, _state: &mut S, _id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let h = helpers.match_first_type_mut::<QemuAsanHelper>().unwrap();
    h.read_n(addr, 2);
}

pub fn trace_read4_asan<I, QT, S>(helpers: &mut QT, _state: &mut S, _id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let h = helpers.match_first_type_mut::<QemuAsanHelper>().unwrap();
    h.read_n(addr, 4);
}

pub fn trace_read8_asan<I, QT, S>(helpers: &mut QT, _state: &mut S, _id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let h = helpers.match_first_type_mut::<QemuAsanHelper>().unwrap();
    h.read_n(addr, 8);
}

pub fn trace_read_n_asan<I, QT, S>(
    helpers: &mut QT,
    _state: &mut S,
    _id: u64,
    addr: u64,
    size: usize,
) where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let h = helpers.match_first_type_mut::<QemuAsanHelper>().unwrap();
    h.read_n(addr, size);
}

pub fn trace_write1_asan<I, QT, S>(helpers: &mut QT, _state: &mut S, _id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let h = helpers.match_first_type_mut::<QemuAsanHelper>().unwrap();
    h.write_n(addr, 1);
}

pub fn trace_write2_asan<I, QT, S>(helpers: &mut QT, _state: &mut S, _id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let h = helpers.match_first_type_mut::<QemuAsanHelper>().unwrap();
    h.write_n(addr, 2);
}

pub fn trace_write4_asan<I, QT, S>(helpers: &mut QT, _state: &mut S, _id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let h = helpers.match_first_type_mut::<QemuAsanHelper>().unwrap();
    h.write_n(addr, 4);
}

pub fn trace_write8_asan<I, QT, S>(helpers: &mut QT, _state: &mut S, _id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let h = helpers.match_first_type_mut::<QemuAsanHelper>().unwrap();
    h.write_n(addr, 8);
}

pub fn trace_write_n_asan<I, QT, S>(
    helpers: &mut QT,
    _state: &mut S,
    _id: u64,
    addr: u64,
    size: usize,
) where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let h = helpers.match_first_type_mut::<QemuAsanHelper>().unwrap();
    h.read_n(addr, size);
}

pub fn qasan_fake_syscall<I, QT, S>(
    helpers: &mut QT,
    _state: &mut S,
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
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    if sys_num == QASAN_FAKESYS_NR {
        let h = helpers.match_first_type_mut::<QemuAsanHelper>().unwrap();
        let mut r = 0;
        match QasanAction::try_from(a0).expect("Invalid QASan action number") {
            QasanAction::CheckLoad => {
                h.read_n(a1, a2 as usize);
            }
            QasanAction::CheckStore => {
                h.write_n(a1, a2 as usize);
            }
            QasanAction::Poison => {
                h.poison(a1, a2 as usize, PoisonKind::try_from(a3 as u8).unwrap());
            }
            QasanAction::UnPoison => {
                h.unpoison(a1, a2 as usize);
            }
            QasanAction::IsPoison => {
                if h.is_poisoned(a1, a2 as usize) {
                    r = 1;
                }
            }
            QasanAction::Alloc => {
                h.alloc(a1, a2);
            }
            QasanAction::Dealloc => {
                h.dealloc(a1);
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
            _ => {}
        }
        SyscallHookResult::new(Some(r))
    } else {
        SyscallHookResult::new(None)
    }
}
