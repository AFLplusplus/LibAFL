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

use crate::{emu, emu::SKIP_EXEC_HOOK};

static mut GEN_EDGE_HOOK_PTR: *const c_void = ptr::null();
static mut GEN_BLOCK_HOOK_PTR: *const c_void = ptr::null();

extern "C" fn gen_edge_hook_wrapper<S>(src: u64, dst: u64) -> u32 {
    unsafe {
        let state = (GLOBAL_STATE.state_ptr as *mut S).as_mut().unwrap();
        let func: fn(&mut S, u64, u64) -> Option<u32> = transmute(GEN_EDGE_HOOK_PTR);
        if let Some(id) = (func)(state, src, dst) {
            id
        } else {
            SKIP_EXEC_HOOK
        }
    }
}

extern "C" fn gen_block_hook_wrapper<S>(addr: u64) -> u32 {
    unsafe {
        let state = (GLOBAL_STATE.state_ptr as *mut S).as_mut().unwrap();
        let func: fn(&mut S, u64) -> Option<u32> = transmute(GEN_BLOCK_HOOK_PTR);
        if let Some(id) = (func)(state, addr) {
            id
        } else {
            SKIP_EXEC_HOOK
        }
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

    pub fn hook_edge_generation(&self, hook: fn(&mut S, u64, u64) -> Option<u32>) {
        unsafe { GEN_EDGE_HOOK_PTR = hook as *const _ };
        emu::set_gen_edge_hook(gen_edge_hook_wrapper::<S>);
    }

    pub fn hook_edge_execution(&self, hook: extern "C" fn(u32)) {
        emu::set_exec_edge_hook(hook);
    }

    pub fn hook_block_generation(&self, hook: fn(&mut S, u64) -> Option<u32>) {
        unsafe { GEN_BLOCK_HOOK_PTR = hook as *const _ };
        emu::set_gen_block_hook(gen_block_hook_wrapper::<S>);
    }

    pub fn hook_block_execution(&self, hook: extern "C" fn(u64)) {
        emu::set_exec_block_hook(hook);
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
