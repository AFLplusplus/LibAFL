use crate::helper::{FridaInstrumentationHelper, FridaRuntimeTuple};

use core::fmt::{self, Debug, Formatter};
use frida_gum::{
    stalker::{NoneEventSink, Stalker},
    Gum, MemoryRange, NativePointer,
};
use std::{ffi::c_void, marker::PhantomData};

use libafl::{
    executors::{Executor, ExitKind, HasObservers, InProcessExecutor},
    inputs::{HasTargetBytes, Input},
    observers::ObserversTuple,
    Error,
};

#[cfg(unix)]
use crate::asan::errors::ASAN_ERRORS;

#[cfg(windows)]
use libafl::executors::inprocess::{HasInProcessHandlers, InProcessHandlers};

/// The [`FridaInProcessExecutor`] is an [`Executor`] that executes the target in the same process, usinig [`frida`](https://frida.re/) for binary-only instrumentation.
pub struct FridaInProcessExecutor<'a, 'b, 'c, H, I, OT, RT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple<I, S>,
{
    base: InProcessExecutor<'a, H, I, OT, S>,
    /// Frida's dynamic rewriting engine
    stalker: Stalker<'a>,
    /// User provided callback for instrumentation
    helper: &'c mut FridaInstrumentationHelper<'b, RT>,
    followed: bool,
    _phantom: PhantomData<&'b u8>,
}

impl<'a, 'b, 'c, H, I, OT, RT, S> Debug for FridaInProcessExecutor<'a, 'b, 'c, H, I, OT, RT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple<I, S>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FridaInProcessExecutor")
            .field("base", &self.base)
            .field("helper", &self.helper)
            .field("followed", &self.followed)
            .finish_non_exhaustive()
    }
}

impl<'a, 'b, 'c, EM, H, I, OT, RT, S, Z> Executor<EM, I, S, Z>
    for FridaInProcessExecutor<'a, 'b, 'c, H, I, OT, RT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input + HasTargetBytes,
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
        self.helper.pre_exec(input)?;
        if self.helper.stalker_enabled() {
            if self.followed {
                self.stalker.activate(NativePointer(core::ptr::null_mut()));
            } else {
                self.followed = true;
                self.stalker
                    .follow_me::<NoneEventSink>(self.helper.transformer(), None);
            }
        }
        let res = self.base.run_target(fuzzer, state, mgr, input);
        if self.helper.stalker_enabled() {
            self.stalker.deactivate();
        }
        #[cfg(unix)]
        unsafe {
            if ASAN_ERRORS.is_some() && !ASAN_ERRORS.as_ref().unwrap().is_empty() {
                println!("Crashing target as it had ASAN errors");
                libc::raise(libc::SIGABRT);
            }
        }
        self.helper.post_exec(input)?;
        res
    }
}

impl<'a, 'b, 'c, H, I, OT, RT, S> HasObservers<I, OT, S>
    for FridaInProcessExecutor<'a, 'b, 'c, H, I, OT, RT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple<I, S>,
{
    #[inline]
    fn observers(&self) -> &OT {
        self.base.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        self.base.observers_mut()
    }
}

impl<'a, 'b, 'c, H, I, OT, S, RT> FridaInProcessExecutor<'a, 'b, 'c, H, I, OT, RT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple<I, S>,
    RT: FridaRuntimeTuple,
{
    /// Creates a new [`FridaInProcessExecutor`]
    pub fn new(
        gum: &'a Gum,
        base: InProcessExecutor<'a, H, I, OT, S>,
        helper: &'c mut FridaInstrumentationHelper<'b, RT>,
    ) -> Self {
        let mut stalker = Stalker::new(gum);
        // Include the current module (the fuzzer) in stalked ranges. We clone the ranges so that
        // we don't add it to the INSTRUMENTED ranges.
        let mut ranges = helper.ranges().clone();
        for module in frida_gum::Module::enumerate_modules() {
            if module.base_address < Self::new as usize
                && (Self::new as usize) < module.base_address + module.size
            {
                ranges.insert(
                    module.base_address..(module.base_address + module.size),
                    (0xffff, "fuzzer".to_string()),
                );
                break;
            }
        }
        for range in ranges.gaps(&(0..usize::MAX)) {
            println!("excluding range: {:x}-{:x}", range.start, range.end);
            stalker.exclude(&MemoryRange::new(
                NativePointer(range.start as *mut c_void),
                range.end - range.start,
            ));
        }

        Self {
            base,
            stalker,
            helper,
            followed: false,
            _phantom: PhantomData,
        }
    }
}

#[cfg(windows)]
impl<'a, 'b, 'c, H, I, OT, RT, S> HasInProcessHandlers
    for FridaInProcessExecutor<'a, 'b, 'c, H, I, OT, RT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple<I, S>,
    RT: FridaRuntimeTuple,
{
    /// the timeout handler
    #[inline]
    fn inprocess_handlers(&self) -> &InProcessHandlers {
        &self.base.handlers()
    }
}
