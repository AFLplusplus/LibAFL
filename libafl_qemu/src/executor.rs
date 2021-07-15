use core::{ffi::c_void, mem::transmute, ptr};

use libafl::{
    corpus::Corpus,
    events::{EventFirer, EventRestarter},
    executors::{inprocess::GLOBAL_STATE, Executor, ExitKind, HasObservers, InProcessExecutor},
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::Input,
    observers::ObserversTuple,
    state::{HasClientPerfStats, HasSolutions},
    Error,
};

pub use crate::emu::SyscallHookResult;
use crate::{emu, emu::SKIP_EXEC_HOOK};

static mut GEN_EDGE_HOOK_PTR: *const c_void = ptr::null();
static mut GEN_BLOCK_HOOK_PTR: *const c_void = ptr::null();
static mut GEN_CMP_HOOK_PTR: *const c_void = ptr::null();

extern "C" fn gen_edge_hook_wrapper<S>(src: u64, dst: u64) -> u32 {
    unsafe {
        let state = (GLOBAL_STATE.state_ptr as *mut S).as_mut().unwrap();
        let func: fn(&mut S, u64, u64) -> Option<u32> = transmute(GEN_EDGE_HOOK_PTR);
        (func)(state, src, dst).map_or(SKIP_EXEC_HOOK, |id| id)
    }
}

extern "C" fn gen_block_hook_wrapper<S>(addr: u64) -> u32 {
    unsafe {
        let state = (GLOBAL_STATE.state_ptr as *mut S).as_mut().unwrap();
        let func: fn(&mut S, u64) -> Option<u32> = transmute(GEN_BLOCK_HOOK_PTR);
        (func)(state, addr).map_or(SKIP_EXEC_HOOK, |id| id)
    }
}

extern "C" fn gen_cmp_hook_wrapper<S>(addr: u64, size: u32) -> u32 {
    unsafe {
        let state = (GLOBAL_STATE.state_ptr as *mut S).as_mut().unwrap();
        let func: fn(&mut S, u64, usize) -> Option<u32> = transmute(GEN_CMP_HOOK_PTR);
        (func)(state, addr, size as usize).map_or(SKIP_EXEC_HOOK, |id| id)
    }
}

pub struct QemuExecutor<'a, H, I, OT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
{
    inner: InProcessExecutor<'a, H, I, OT, S>,
}

impl<'a, H, I, OT, S> QemuExecutor<'a, H, I, OT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
{
    pub fn new<EM, OC, OF, Z>(
        harness_fn: &'a mut H,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<I, S> + EventRestarter<S>,
        OC: Corpus<I>,
        OF: Feedback<I, S>,
        S: HasSolutions<OC, I> + HasClientPerfStats,
        Z: HasObjective<I, OF, S>,
    {
        Ok(Self {
            inner: InProcessExecutor::new(harness_fn, observers, fuzzer, state, event_mgr)?,
        })
    }

    pub fn inner(&self) -> &InProcessExecutor<'a, H, I, OT, S> {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut InProcessExecutor<'a, H, I, OT, S> {
        &mut self.inner
    }

    #[allow(clippy::unused_self)]
    pub fn hook_edge_generation(&self, hook: fn(&mut S, src: u64, dest: u64) -> Option<u32>) {
        unsafe { GEN_EDGE_HOOK_PTR = hook as *const _ };
        emu::set_gen_edge_hook(gen_edge_hook_wrapper::<S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_edge_execution(&self, hook: extern "C" fn(id: u32)) {
        emu::set_exec_edge_hook(hook);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_block_generation(&self, hook: fn(&mut S, addr: u64) -> Option<u32>) {
        unsafe { GEN_BLOCK_HOOK_PTR = hook as *const _ };
        emu::set_gen_block_hook(gen_block_hook_wrapper::<S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_block_execution(&self, hook: extern "C" fn(addr: u64)) {
        emu::set_exec_block_hook(hook);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_cmp_generation(&self, hook: fn(&mut S, addr: u64, size: usize) -> Option<u32>) {
        unsafe { GEN_CMP_HOOK_PTR = hook as *const _ };
        emu::set_gen_cmp_hook(gen_cmp_hook_wrapper::<S>);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_cmp1_execution(&self, hook: extern "C" fn(id: u32, v0: u8, v1: u8)) {
        emu::set_exec_cmp1_hook(hook);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_cmp2_execution(&self, hook: extern "C" fn(id: u32, v0: u16, v1: u16)) {
        emu::set_exec_cmp2_hook(hook);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_cmp4_execution(&self, hook: extern "C" fn(id: u32, v0: u32, v1: u32)) {
        emu::set_exec_cmp4_hook(hook);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_cmp8_execution(&self, hook: extern "C" fn(id: u32, v0: u64, v1: u64)) {
        emu::set_exec_cmp8_hook(hook);
    }

    #[allow(clippy::unused_self)]
    pub fn hook_syscalls(
        &self,
        hook: extern "C" fn(i32, u64, u64, u64, u64, u64, u64, u64, u64) -> SyscallHookResult,
    ) {
        emu::set_syscall_hook(hook);
    }
}

impl<'a, EM, H, I, OT, S, Z> Executor<EM, I, S, Z> for QemuExecutor<'a, H, I, OT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        self.inner.run_target(fuzzer, state, mgr, input)
    }
}

impl<'a, H, I, OT, S> HasObservers<I, OT, S> for QemuExecutor<'a, H, I, OT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
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
