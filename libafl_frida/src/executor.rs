use crate::helper::FridaHelper;

use std::{ffi::c_void, marker::PhantomData};

use frida_gum::{
    stalker::{NoneEventSink, Stalker},
    Gum, NativePointer,
};

use libafl::{
    executors::{Executor, ExitKind, HasObservers, InProcessExecutor},
    inputs::{HasTargetBytes, Input},
    observers::ObserversTuple,
    Error,
};

use crate::asan_errors::ASAN_ERRORS;

pub struct FridaInProcessExecutor<'a, 'b, 'c, FH, H, I, OT, S>
where
    FH: FridaHelper<'b>,
    H: FnMut(&I) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple<I, S>,
{
    base: InProcessExecutor<'a, H, I, OT, S>,
    /// Frida's dynamic rewriting engine
    stalker: Stalker<'a>,
    /// User provided callback for instrumentation
    helper: &'c mut FH,
    followed: bool,
    _phantom: PhantomData<&'b u8>,
}

impl<'a, 'b, 'c, EM, FH, H, I, OT, S, Z> Executor<EM, I, S, Z>
    for FridaInProcessExecutor<'a, 'b, 'c, FH, H, I, OT, S>
where
    FH: FridaHelper<'b>,
    H: FnMut(&I) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple<I, S>,
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
        self.helper.pre_exec(input);
        if self.helper.stalker_enabled() {
            if self.followed {
                self.stalker.activate(NativePointer(
                    self.base.harness_mut() as *mut _ as *mut c_void
                ));
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
        if unsafe { ASAN_ERRORS.is_some() && !ASAN_ERRORS.as_ref().unwrap().is_empty() } {
            println!("Crashing target as it had ASAN errors");
            unsafe {
                libc::raise(libc::SIGABRT);
            }
        }
        self.helper.post_exec(input);
        res
    }
}

impl<'a, 'b, 'c, FH, H, I, OT, S> HasObservers<I, OT, S>
    for FridaInProcessExecutor<'a, 'b, 'c, FH, H, I, OT, S>
where
    FH: FridaHelper<'b>,
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

impl<'a, 'b, 'c, FH, H, I, OT, S> FridaInProcessExecutor<'a, 'b, 'c, FH, H, I, OT, S>
where
    FH: FridaHelper<'b>,
    H: FnMut(&I) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple<I, S>,
{
    pub fn new(gum: &'a Gum, base: InProcessExecutor<'a, H, I, OT, S>, helper: &'c mut FH) -> Self {
        let mut stalker = Stalker::new(gum);

        #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
        for range in helper.ranges().gaps(&(0..usize::MAX)) {
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
