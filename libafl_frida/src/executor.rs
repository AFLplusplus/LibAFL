use alloc::rc::Rc;
use core::{
    cell::RefCell,
    ffi::c_void,
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};
#[cfg(all(windows, not(test)))]
use std::process::abort;

use frida_gum::{
    Gum, MemoryRange, NativePointer,
    stalker::{NoneEventSink, Stalker},
};
#[cfg(windows)]
use libafl::executors::{hooks::inprocess::InProcessHooks, inprocess::HasInProcessHooks};
use libafl::{
    Error,
    executors::{Executor, ExitKind, HasObservers, InProcessExecutor},
    inputs::{Input, NopTargetBytesConverter, TargetBytesConverter},
    observers::ObserversTuple,
    state::{HasCurrentTestcase, HasExecutions, HasSolutions},
};
use libafl_bolts::{AsSlice, tuples::RefIndexable};

#[cfg(not(test))]
use crate::asan::errors::AsanErrors;
use crate::helper::{FridaInstrumentationHelper, FridaRuntimeTuple};
#[cfg(windows)]
use crate::windows_hooks::initialize;

/// The [`FridaInProcessExecutor`] is an [`Executor`] that executes the target in the same process, usinig [`frida`](https://frida.re/) for binary-only instrumentation.
pub struct FridaInProcessExecutor<'a, 'b, EM, H, I, OT, RT, S, TC, Z> {
    base: InProcessExecutor<'a, EM, H, I, OT, S, Z>,
    /// `thread_id` for the Stalker
    thread_id: Option<u32>,
    /// Frida's dynamic rewriting engine
    stalker: Stalker,
    /// User provided callback for instrumentation
    helper: Rc<RefCell<FridaInstrumentationHelper<'b, RT>>>,
    target_bytes_converter: TC,
    followed: bool,
    _phantom: PhantomData<&'b u8>,
}

impl<EM, H, I, OT, RT, S, TC, Z> Debug
    for FridaInProcessExecutor<'_, '_, EM, H, I, OT, RT, S, TC, Z>
where
    OT: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FridaInProcessExecutor")
            .field("base", &self.base)
            .field("helper", &self.helper.borrow_mut())
            .field("followed", &self.followed)
            .finish_non_exhaustive()
    }
}

impl<EM, H, I, OT, RT, S, TC, Z> Executor<EM, I, S, Z>
    for FridaInProcessExecutor<'_, '_, EM, H, I, OT, RT, S, TC, Z>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    S: HasExecutions,
    S: HasCurrentTestcase<I>,
    S: HasSolutions<I>,
    TC: TargetBytesConverter<I>,
    OT: ObserversTuple<I, S>,
    RT: FridaRuntimeTuple,
{
    /// Instruct the target about the input and run
    #[inline]
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        let target_bytes = self.target_bytes_converter.to_target_bytes(input);
        self.helper.borrow_mut().pre_exec(target_bytes.as_slice())?;
        if self.helper.borrow_mut().stalker_enabled() {
            if !(self.followed) {
                self.followed = true;
                let helper_binding = self.helper.borrow_mut();
                let transformer = helper_binding.transformer();
                if let Some(thread_id) = self.thread_id {
                    self.stalker.follow::<NoneEventSink>(
                        thread_id.try_into().unwrap(),
                        transformer,
                        None,
                    );
                } else {
                    self.stalker.follow_me::<NoneEventSink>(transformer, None);
                    self.stalker.deactivate();
                }
            }
            // We removed the fuzzer from the stalked ranges,
            // but we need to pass the harness entry point
            // so that Stalker knows to pick it despite the module being excluded
            let harness_fn_ref: &H = self.base.harness();
            let ptr: *const H = harness_fn_ref as *const H;
            log::info!("Activating Stalker for {ptr:p}");
            self.stalker.activate(NativePointer(ptr as *mut c_void));
        }
        let res = self.base.run_target(fuzzer, state, mgr, input);
        if self.helper.borrow_mut().stalker_enabled() {
            self.stalker.deactivate();
        }

        #[cfg(not(test))]
        unsafe {
            if !AsanErrors::get_mut_blocking().is_empty() {
                log::error!("Crashing target as it had ASan errors");
                libc::raise(libc::SIGABRT);
                #[cfg(windows)]
                abort();
            }
        }
        self.helper
            .borrow_mut()
            .post_exec(target_bytes.as_slice())?;
        res
    }
}

impl<EM, H, I, OT, RT, S, TC, Z> HasObservers
    for FridaInProcessExecutor<'_, '_, EM, H, I, OT, RT, S, TC, Z>
{
    type Observers = OT;
    #[inline]
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        self.base.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        self.base.observers_mut()
    }
}

impl<'a, 'b, EM, H, I, OT, RT, S, Z>
    FridaInProcessExecutor<'a, 'b, EM, H, I, OT, RT, S, NopTargetBytesConverter<I>, Z>
where
    RT: FridaRuntimeTuple,
{
    /// Creates a new [`FridaInProcessExecutor`].
    pub fn new(
        gum: &'a Gum,
        base: InProcessExecutor<'a, EM, H, I, OT, S, Z>,
        helper: Rc<RefCell<FridaInstrumentationHelper<'b, RT>>>,
    ) -> Self {
        FridaInProcessExecutor::with_target_bytes_converter(
            gum,
            base,
            helper,
            None,
            NopTargetBytesConverter::new(),
        )
    }

    /// Creates a new [`FridaInProcessExecutor`] tracking the given `thread_id`.
    pub fn on_thread(
        gum: &'a Gum,
        base: InProcessExecutor<'a, EM, H, I, OT, S, Z>,
        helper: Rc<RefCell<FridaInstrumentationHelper<'b, RT>>>,
        thread_id: u32,
    ) -> Self {
        FridaInProcessExecutor::with_target_bytes_converter(
            gum,
            base,
            helper,
            Some(thread_id),
            NopTargetBytesConverter::new(),
        )
    }
}

impl<'a, 'b, EM, H, I, OT, RT, S, TC, Z> FridaInProcessExecutor<'a, 'b, EM, H, I, OT, RT, S, TC, Z>
where
    RT: FridaRuntimeTuple,
{
    /// Creates a new [`FridaInProcessExecutor`].
    pub fn with_target_bytes_converter(
        gum: &'a Gum,
        base: InProcessExecutor<'a, EM, H, I, OT, S, Z>,
        helper: Rc<RefCell<FridaInstrumentationHelper<'b, RT>>>,
        thread_id: Option<u32>,
        target_bytes_converter: TC,
    ) -> Self {
        let mut stalker = Stalker::new(gum);
        let ranges = helper.borrow_mut().ranges().clone();
        for module in frida_gum::Process::obtain(gum).enumerate_modules() {
            let range = module.range();
            if (range.base_address().0 as usize) < Self::with_target_bytes_converter as usize
                && (Self::with_target_bytes_converter as usize as u64)
                    < range.base_address().0 as u64 + range.size() as u64
            {
                log::info!(
                    "Fuzzer range: {:x}-{:x}",
                    range.base_address().0 as u64,
                    range.base_address().0 as u64 + range.size() as u64
                );
                // Exclude the fuzzer from the stalked ranges, it is really unnecessary and harmfull.
                // Otherwise, Stalker starts messing with our hooks and their callbacks
                // wrecking havoc and causing deadlocks
                stalker.exclude(&MemoryRange::new(
                    NativePointer(range.base_address().0),
                    range.size(),
                ));
                break;
            }
        }

        log::info!(
            "disable_excludes: {:}",
            helper.borrow_mut().disable_excludes
        );
        if !helper.borrow_mut().disable_excludes {
            for range in ranges.gaps(&(0..u64::MAX)) {
                log::info!("excluding range: {:x}-{:x}", range.start, range.end);
                stalker.exclude(&MemoryRange::new(
                    NativePointer(range.start as *mut c_void),
                    usize::try_from(range.end - range.start).unwrap_or_else(|err| {
                        panic!("Address out of usize range: {range:?} - {err}")
                    }),
                ));
            }
        }

        #[cfg(windows)]
        initialize(gum);

        Self {
            base,
            thread_id,
            stalker,
            helper,
            target_bytes_converter,
            followed: false,
            _phantom: PhantomData,
        }
    }
}

#[cfg(windows)]
impl<'a, 'b, EM, H, I, OT, RT, S, TC, Z> HasInProcessHooks<I, S>
    for FridaInProcessExecutor<'a, 'b, EM, H, I, OT, RT, S, TC, Z>
where
    H: FnMut(&I) -> ExitKind,
    S: HasSolutions<I> + HasCurrentTestcase<I> + HasExecutions,
    I: Input,
    TC: TargetBytesConverter<I>,
    OT: ObserversTuple<I, S>,
    RT: FridaRuntimeTuple,
{
    /// the timeout handler
    #[inline]
    fn inprocess_hooks(&self) -> &InProcessHooks<I, S> {
        &self.base.hooks().0
    }

    /// the timeout handler
    #[inline]
    fn inprocess_hooks_mut(&mut self) -> &mut InProcessHooks<I, S> {
        &mut self.base.hooks_mut().0
    }
}
