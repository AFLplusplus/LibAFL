use core::{ffi::c_void, mem::transmute, ptr};

use libafl::{
    corpus::Corpus,
    events::{EventFirer, EventRestarter},
    executors::{
        inprocess::inprocess_get_state, Executor, ExitKind, HasObservers, InProcessExecutor,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::Input,
    observers::ObserversTuple,
    state::{HasClientPerfMonitor, HasSolutions},
    Error,
};

pub use crate::emu::SyscallHookResult;
use crate::{emu, emu::SKIP_EXEC_HOOK, helper::QemuHelperTuple};

static mut QEMU_HELPERS_PTR: *const c_void = ptr::null();

static mut GEN_EDGE_HOOK_PTR: *const c_void = ptr::null();
extern "C" fn gen_edge_hook_wrapper<I, QT, S>(src: u64, dst: u64) -> u64
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap();
        let state = inprocess_get_state::<S>().unwrap();
        let func: fn(&mut QT, &mut S, u64, u64) -> Option<u64> = transmute(GEN_EDGE_HOOK_PTR);
        (func)(helpers, state, src, dst).map_or(SKIP_EXEC_HOOK, |id| id)
    }
}

static mut EDGE_HOOKS: Vec<*const c_void> = vec![];
extern "C" fn edge_hooks_wrapper<I, QT, S>(id: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let helpers = unsafe { (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap() };
    let state = inprocess_get_state::<S>().unwrap();
    for hook in unsafe { &EDGE_HOOKS } {
        let func: fn(&mut QT, &mut S, u64) = unsafe { transmute(*hook) };
        (func)(helpers, state, id);
    }
}

static mut GEN_BLOCK_HOOK_PTR: *const c_void = ptr::null();
extern "C" fn gen_block_hook_wrapper<I, QT, S>(pc: u64) -> u64
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap();
        let state = inprocess_get_state::<S>().unwrap();
        let func: fn(&mut QT, &mut S, u64) -> Option<u64> = transmute(GEN_EDGE_HOOK_PTR);
        (func)(helpers, state, pc).map_or(SKIP_EXEC_HOOK, |id| id)
    }
}

static mut BLOCK_HOOKS: Vec<*const c_void> = vec![];
extern "C" fn block_hooks_wrapper<I, QT, S>(id: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let helpers = unsafe { (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap() };
    let state = inprocess_get_state::<S>().unwrap();
    for hook in unsafe { &BLOCK_HOOKS } {
        let func: fn(&mut QT, &mut S, u64) = unsafe { transmute(*hook) };
        (func)(helpers, state, id);
    }
}

static mut GEN_READ_HOOK_PTR: *const c_void = ptr::null();
extern "C" fn gen_read_hook_wrapper<I, QT, S>(size: u32) -> u64
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap();
        let state = inprocess_get_state::<S>().unwrap();
        let func: fn(&mut QT, &mut S, usize) -> Option<u64> = transmute(GEN_READ_HOOK_PTR);
        (func)(helpers, state, size as usize).map_or(SKIP_EXEC_HOOK, |id| id)
    }
}

static mut GEN_WRITE_HOOK_PTR: *const c_void = ptr::null();
extern "C" fn gen_write_hook_wrapper<I, QT, S>(size: u32) -> u64
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap();
        let state = inprocess_get_state::<S>().unwrap();
        let func: fn(&mut QT, &mut S, usize) -> Option<u64> = transmute(GEN_WRITE_HOOK_PTR);
        (func)(helpers, state, size as usize).map_or(SKIP_EXEC_HOOK, |id| id)
    }
}

static mut READ1_HOOKS: Vec<*const c_void> = vec![];
extern "C" fn read1_hooks_wrapper<I, QT, S>(id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let helpers = unsafe { (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap() };
    let state = inprocess_get_state::<S>().unwrap();
    for hook in unsafe { &READ1_HOOKS } {
        let func: fn(&mut QT, &mut S, u64, u64) = unsafe { transmute(*hook) };
        (func)(helpers, state, id, addr);
    }
}

static mut READ2_HOOKS: Vec<*const c_void> = vec![];
extern "C" fn read2_hooks_wrapper<I, QT, S>(id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let helpers = unsafe { (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap() };
    let state = inprocess_get_state::<S>().unwrap();
    for hook in unsafe { &READ2_HOOKS } {
        let func: fn(&mut QT, &mut S, u64, u64) = unsafe { transmute(*hook) };
        (func)(helpers, state, id, addr);
    }
}

static mut READ4_HOOKS: Vec<*const c_void> = vec![];
extern "C" fn read4_hooks_wrapper<I, QT, S>(id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let helpers = unsafe { (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap() };
    let state = inprocess_get_state::<S>().unwrap();
    for hook in unsafe { &READ4_HOOKS } {
        let func: fn(&mut QT, &mut S, u64, u64) = unsafe { transmute(*hook) };
        (func)(helpers, state, id, addr);
    }
}

static mut READ8_HOOKS: Vec<*const c_void> = vec![];
extern "C" fn read8_hooks_wrapper<I, QT, S>(id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let helpers = unsafe { (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap() };
    let state = inprocess_get_state::<S>().unwrap();
    for hook in unsafe { &READ8_HOOKS } {
        let func: fn(&mut QT, &mut S, u64, u64) = unsafe { transmute(*hook) };
        (func)(helpers, state, id, addr);
    }
}

static mut READ_N_HOOKS: Vec<*const c_void> = vec![];
extern "C" fn read_n_hooks_wrapper<I, QT, S>(id: u64, addr: u64, size: u32)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let helpers = unsafe { (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap() };
    let state = inprocess_get_state::<S>().unwrap();
    for hook in unsafe { &READ_N_HOOKS } {
        let func: fn(&mut QT, &mut S, u64, u64, usize) = unsafe { transmute(*hook) };
        (func)(helpers, state, id, addr, size as usize);
    }
}

static mut WRITE1_HOOKS: Vec<*const c_void> = vec![];
extern "C" fn write1_hooks_wrapper<I, QT, S>(id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let helpers = unsafe { (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap() };
    let state = inprocess_get_state::<S>().unwrap();
    for hook in unsafe { &WRITE1_HOOKS } {
        let func: fn(&mut QT, &mut S, u64, u64) = unsafe { transmute(*hook) };
        (func)(helpers, state, id, addr);
    }
}

static mut WRITE2_HOOKS: Vec<*const c_void> = vec![];
extern "C" fn write2_hooks_wrapper<I, QT, S>(id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let helpers = unsafe { (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap() };
    let state = inprocess_get_state::<S>().unwrap();
    for hook in unsafe { &WRITE2_HOOKS } {
        let func: fn(&mut QT, &mut S, u64, u64) = unsafe { transmute(*hook) };
        (func)(helpers, state, id, addr);
    }
}

static mut WRITE4_HOOKS: Vec<*const c_void> = vec![];
extern "C" fn write4_hooks_wrapper<I, QT, S>(id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let helpers = unsafe { (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap() };
    let state = inprocess_get_state::<S>().unwrap();
    for hook in unsafe { &WRITE4_HOOKS } {
        let func: fn(&mut QT, &mut S, u64, u64) = unsafe { transmute(*hook) };
        (func)(helpers, state, id, addr);
    }
}

static mut WRITE8_HOOKS: Vec<*const c_void> = vec![];
extern "C" fn write8_hooks_wrapper<I, QT, S>(id: u64, addr: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let helpers = unsafe { (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap() };
    let state = inprocess_get_state::<S>().unwrap();
    for hook in unsafe { &WRITE8_HOOKS } {
        let func: fn(&mut QT, &mut S, u64, u64) = unsafe { transmute(*hook) };
        (func)(helpers, state, id, addr);
    }
}

static mut WRITE_N_HOOKS: Vec<*const c_void> = vec![];
extern "C" fn write_n_hooks_wrapper<I, QT, S>(id: u64, addr: u64, size: u32)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let helpers = unsafe { (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap() };
    let state = inprocess_get_state::<S>().unwrap();
    for hook in unsafe { &WRITE_N_HOOKS } {
        let func: fn(&mut QT, &mut S, u64, u64, usize) = unsafe { transmute(*hook) };
        (func)(helpers, state, id, addr, size as usize);
    }
}

static mut GEN_CMP_HOOK_PTR: *const c_void = ptr::null();
extern "C" fn gen_cmp_hook_wrapper<I, QT, S>(pc: u64, size: u32) -> u64
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    unsafe {
        let helpers = (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap();
        let state = inprocess_get_state::<S>().unwrap();
        let func: fn(&mut QT, &mut S, u64, usize) -> Option<u64> = transmute(GEN_CMP_HOOK_PTR);
        (func)(helpers, state, pc, size as usize).map_or(SKIP_EXEC_HOOK, |id| id)
    }
}

static mut CMP1_HOOKS: Vec<*const c_void> = vec![];
extern "C" fn cmp1_hooks_wrapper<I, QT, S>(id: u64, v0: u8, v1: u8)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let helpers = unsafe { (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap() };
    let state = inprocess_get_state::<S>().unwrap();
    for hook in unsafe { &CMP1_HOOKS } {
        let func: fn(&mut QT, &mut S, u64, u8, u8) = unsafe { transmute(*hook) };
        (func)(helpers, state, id, v0, v1);
    }
}

static mut CMP2_HOOKS: Vec<*const c_void> = vec![];
extern "C" fn cmp2_hooks_wrapper<I, QT, S>(id: u64, v0: u16, v1: u16)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let helpers = unsafe { (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap() };
    let state = inprocess_get_state::<S>().unwrap();
    for hook in unsafe { &CMP2_HOOKS } {
        let func: fn(&mut QT, &mut S, u64, u16, u16) = unsafe { transmute(*hook) };
        (func)(helpers, state, id, v0, v1);
    }
}

static mut CMP4_HOOKS: Vec<*const c_void> = vec![];
extern "C" fn cmp4_hooks_wrapper<I, QT, S>(id: u64, v0: u32, v1: u32)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let helpers = unsafe { (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap() };
    let state = inprocess_get_state::<S>().unwrap();
    for hook in unsafe { &CMP4_HOOKS } {
        let func: fn(&mut QT, &mut S, u64, u32, u32) = unsafe { transmute(*hook) };
        (func)(helpers, state, id, v0, v1);
    }
}

static mut CMP8_HOOKS: Vec<*const c_void> = vec![];
extern "C" fn cmp8_hooks_wrapper<I, QT, S>(id: u64, v0: u64, v1: u64)
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let helpers = unsafe { (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap() };
    let state = inprocess_get_state::<S>().unwrap();
    for hook in unsafe { &CMP8_HOOKS } {
        let func: fn(&mut QT, &mut S, u64, u64, u64) = unsafe { transmute(*hook) };
        (func)(helpers, state, id, v0, v1);
    }
}

static mut SYSCALL_HOOKS: Vec<*const c_void> = vec![];
extern "C" fn syscall_hooks_wrapper<I, QT, S>(
    sys_num: i32,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
) -> SyscallHookResult
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let helpers = unsafe { (QEMU_HELPERS_PTR as *mut QT).as_mut().unwrap() };
    let state = inprocess_get_state::<S>().unwrap();
    let mut res = SyscallHookResult::new(None);
    for hook in unsafe { &SYSCALL_HOOKS } {
        #[allow(clippy::type_complexity)]
        let func: fn(
            &mut QT,
            &mut S,
            i32,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
        ) -> SyscallHookResult = unsafe { transmute(*hook) };
        let r = (func)(helpers, state, sys_num, a0, a1, a2, a3, a4, a5, a6, a7);
        if r.skip_syscall {
            res.skip_syscall = true;
            res.retval = r.retval;
        }
    }
    res
}

pub struct QemuExecutor<'a, H, I, OT, QT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
    QT: QemuHelperTuple<I, S>,
{
    helpers: QT,
    inner: InProcessExecutor<'a, H, I, OT, S>,
}

impl<'a, H, I, OT, QT, S> QemuExecutor<'a, H, I, OT, QT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
    QT: QemuHelperTuple<I, S>,
{
    pub fn new<EM, OC, OF, Z>(
        harness_fn: &'a mut H,
        helpers: QT,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<I> + EventRestarter<S>,
        OC: Corpus<I>,
        OF: Feedback<I, S>,
        S: HasSolutions<OC, I> + HasClientPerfMonitor,
        Z: HasObjective<I, OF, S>,
    {
        let slf = Self {
            helpers,
            inner: InProcessExecutor::new(harness_fn, observers, fuzzer, state, event_mgr)?,
        };
        slf.helpers.init_all(&slf);
        Ok(slf)
    }

    pub fn inner(&self) -> &InProcessExecutor<'a, H, I, OT, S> {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut InProcessExecutor<'a, H, I, OT, S> {
        &mut self.inner
    }

    #[allow(clippy::unused_self)]
    pub fn hook_edge_generation(
        &self,
        hook: fn(&mut QT, &mut S, src: u64, dest: u64) -> Option<u64>,
    ) {
        unsafe {
            GEN_EDGE_HOOK_PTR = hook as *const _;
        }
        emu::set_gen_edge_hook(gen_edge_hook_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_edge_execution(&self, hook: fn(&mut QT, &mut S, id: u64)) {
        unsafe {
            EDGE_HOOKS.push(hook as *const _);
        }
        emu::set_exec_edge_hook(edge_hooks_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_block_generation(&self, hook: fn(&mut QT, &mut S, pc: u64) -> Option<u64>) {
        unsafe {
            GEN_BLOCK_HOOK_PTR = hook as *const _;
        }
        emu::set_gen_block_hook(gen_block_hook_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_block_execution(&self, hook: fn(&mut QT, &mut S, id: u64)) {
        unsafe {
            BLOCK_HOOKS.push(hook as *const _);
        }
        emu::set_exec_block_hook(block_hooks_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_read_generation(&self, hook: fn(&mut QT, &mut S, size: usize) -> Option<u64>) {
        unsafe {
            GEN_READ_HOOK_PTR = hook as *const _;
        }
        emu::set_gen_read_hook(gen_read_hook_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_read1_execution(&self, hook: fn(&mut QT, &mut S, id: u64, addr: u64)) {
        unsafe {
            READ1_HOOKS.push(hook as *const _);
        }
        emu::set_exec_read1_hook(read1_hooks_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_read2_execution(&self, hook: fn(&mut QT, &mut S, id: u64, addr: u64)) {
        unsafe {
            READ2_HOOKS.push(hook as *const _);
        }
        emu::set_exec_read2_hook(read2_hooks_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_read4_execution(&self, hook: fn(&mut QT, &mut S, id: u64, addr: u64)) {
        unsafe {
            READ4_HOOKS.push(hook as *const _);
        }
        emu::set_exec_read4_hook(read4_hooks_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_read8_execution(&self, hook: fn(&mut QT, &mut S, id: u64, addr: u64)) {
        unsafe {
            READ8_HOOKS.push(hook as *const _);
        }
        emu::set_exec_read8_hook(read8_hooks_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_read_n_execution(
        &self,
        hook: fn(&mut QT, &mut S, id: u64, addr: u64, size: usize),
    ) {
        unsafe {
            READ_N_HOOKS.push(hook as *const _);
        }
        emu::set_exec_read_n_hook(read_n_hooks_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_write_generation(&self, hook: fn(&mut QT, &mut S, size: usize) -> Option<u64>) {
        unsafe {
            GEN_WRITE_HOOK_PTR = hook as *const _;
        }
        emu::set_gen_write_hook(gen_write_hook_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_write1_execution(&self, hook: fn(&mut QT, &mut S, id: u64, addr: u64)) {
        unsafe {
            WRITE1_HOOKS.push(hook as *const _);
        }
        emu::set_exec_write1_hook(write1_hooks_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_write2_execution(&self, hook: fn(&mut QT, &mut S, id: u64, addr: u64)) {
        unsafe {
            WRITE2_HOOKS.push(hook as *const _);
        }
        emu::set_exec_write2_hook(write2_hooks_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_write4_execution(&self, hook: fn(&mut QT, &mut S, id: u64, addr: u64)) {
        unsafe {
            WRITE4_HOOKS.push(hook as *const _);
        }
        emu::set_exec_write4_hook(write4_hooks_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_write8_execution(&self, hook: fn(&mut QT, &mut S, id: u64, addr: u64)) {
        unsafe {
            WRITE8_HOOKS.push(hook as *const _);
        }
        emu::set_exec_write8_hook(write8_hooks_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_write_n_execution(
        &self,
        hook: fn(&mut QT, &mut S, id: u64, addr: u64, size: usize),
    ) {
        unsafe {
            WRITE_N_HOOKS.push(hook as *const _);
        }
        emu::set_exec_write_n_hook(write_n_hooks_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_cmp_generation(
        &self,
        hook: fn(&mut QT, &mut S, pc: u64, size: usize) -> Option<u64>,
    ) {
        unsafe {
            GEN_CMP_HOOK_PTR = hook as *const _;
        }
        emu::set_gen_cmp_hook(gen_cmp_hook_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_cmp1_execution(&self, hook: fn(&mut QT, &mut S, id: u64, v0: u8, v1: u8)) {
        unsafe {
            CMP1_HOOKS.push(hook as *const _);
        }
        emu::set_exec_cmp1_hook(cmp1_hooks_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_cmp2_execution(&self, hook: fn(&mut QT, &mut S, id: u64, v0: u16, v1: u16)) {
        unsafe {
            CMP2_HOOKS.push(hook as *const _);
        }
        emu::set_exec_cmp2_hook(cmp2_hooks_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_cmp4_execution(&self, hook: fn(&mut QT, &mut S, id: u64, v0: u32, v1: u32)) {
        unsafe {
            CMP4_HOOKS.push(hook as *const _);
        }
        emu::set_exec_cmp4_hook(cmp4_hooks_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_cmp8_execution(&self, hook: fn(&mut QT, &mut S, id: u64, v0: u64, v1: u64)) {
        unsafe {
            CMP8_HOOKS.push(hook as *const _);
        }
        emu::set_exec_cmp8_hook(cmp8_hooks_wrapper::<I, QT, S>);
    }

    #[allow(clippy::unused_self)]
    #[allow(clippy::type_complexity)]
    pub fn hook_syscalls(
        &self,
        hook: fn(
            &mut QT,
            &mut S,
            sys_num: i32,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
        ) -> SyscallHookResult,
    ) {
        unsafe {
            SYSCALL_HOOKS.push(hook as *const _);
        }
        emu::set_syscall_hook(syscall_hooks_wrapper::<I, QT, S>);
    }
}

impl<'a, EM, H, I, OT, QT, S, Z> Executor<EM, I, S, Z> for QemuExecutor<'a, H, I, OT, QT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
    QT: QemuHelperTuple<I, S>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        unsafe { QEMU_HELPERS_PTR = &self.helpers as *const _ as *const c_void };
        self.helpers.pre_exec_all(input);
        let r = self.inner.run_target(fuzzer, state, mgr, input);
        self.helpers.post_exec_all(input);
        unsafe { QEMU_HELPERS_PTR = ptr::null() };
        r
    }
}

impl<'a, H, I, OT, QT, S> HasObservers<I, OT, S> for QemuExecutor<'a, H, I, OT, QT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
    QT: QemuHelperTuple<I, S>,
{
    #[inline]
    fn observers(&self) -> &OT {
        self.inner.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        self.inner.observers_mut()
    }
}
