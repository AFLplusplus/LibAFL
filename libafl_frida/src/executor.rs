use core::fmt::{self, Debug, Formatter};
#[cfg(all(windows, not(test)))]
use std::process::abort;
use std::{ffi::c_void, marker::PhantomData};

use frida_gum::{
    stalker::{NoneEventSink, Stalker},
    Gum, MemoryRange, NativePointer,
};
#[cfg(windows)]
use libafl::{
    corpus::Corpus,
    executors::{hooks::inprocess::InProcessHooks, inprocess::HasInProcessHooks},
    inputs::Input,
    state::{HasCurrentTestcase, HasSolutions},
};
use libafl::{
    executors::{Executor, ExitKind, HasObservers, InProcessExecutor},
    inputs::{NopTargetBytesConverter, TargetBytesConverter},
    observers::ObserversTuple,
    state::HasExecutions,
    Error,
};
use libafl_bolts::{tuples::RefIndexable, AsSlice};

#[cfg(not(test))]
use crate::asan::errors::AsanErrors;
use crate::helper::{FridaInstrumentationHelper, FridaRuntimeTuple};
#[cfg(windows)]
use crate::windows_hooks::initialize;

/// The [`FridaInProcessExecutor`] is an [`Executor`] that executes the target in the same process, usinig [`frida`](https://frida.re/) for binary-only instrumentation.
pub struct FridaInProcessExecutor<'a, 'b, 'c, H, I, OT, RT, S, TC> {
    base: InProcessExecutor<'a, H, I, OT, S>,
    /// `thread_id` for the Stalker
    thread_id: Option<u32>,
    /// Frida's dynamic rewriting engine
    stalker: Stalker,
    /// User provided callback for instrumentation
    helper: &'c mut FridaInstrumentationHelper<'b, RT>,
    target_bytes_converter: TC,
    followed: bool,
    _phantom: PhantomData<&'b u8>,
}

impl<H, I, OT, RT, S, TC> Debug for FridaInProcessExecutor<'_, '_, '_, H, I, OT, RT, S, TC>
where
    OT: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FridaInProcessExecutor")
            .field("base", &self.base)
            .field("helper", &self.helper)
            .field("followed", &self.followed)
            .finish_non_exhaustive()
    }
}

impl<EM, H, I, OT, RT, S, TC, Z> Executor<EM, I, S, Z>
    for FridaInProcessExecutor<'_, '_, '_, H, I, OT, RT, S, TC>
where
    H: FnMut(&I) -> ExitKind,
    S: HasExecutions,
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
        self.helper.pre_exec(target_bytes.as_slice())?;
        if self.helper.stalker_enabled() {
            if self.followed {
                self.stalker.activate(NativePointer(core::ptr::null_mut()));
            } else {
                self.followed = true;
                let transformer = self.helper.transformer();
                if let Some(thread_id) = self.thread_id {
                    self.stalker.follow::<NoneEventSink>(
                        thread_id.try_into().unwrap(),
                        transformer,
                        None,
                    );
                } else {
                    self.stalker.follow_me::<NoneEventSink>(transformer, None);
                }
            }
        }
        let res = self.base.run_target(fuzzer, state, mgr, input);
        if self.helper.stalker_enabled() {
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
        self.helper.post_exec(target_bytes.as_slice())?;
        res
    }
}

impl<H, I, OT, RT, S, TC> HasObservers for FridaInProcessExecutor<'_, '_, '_, H, I, OT, RT, S, TC> {
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

impl<'a, 'b, 'c, H, I, OT, RT, S>
    FridaInProcessExecutor<'a, 'b, 'c, H, I, OT, RT, S, NopTargetBytesConverter<I>>
where
    RT: FridaRuntimeTuple,
{
    /// Creates a new [`FridaInProcessExecutor`].
    pub fn new(
        gum: &'a Gum,
        base: InProcessExecutor<'a, H, I, OT, S>,
        helper: &'c mut FridaInstrumentationHelper<'b, RT>,
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
        base: InProcessExecutor<'a, H, I, OT, S>,
        helper: &'c mut FridaInstrumentationHelper<'b, RT>,
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

impl<'a, 'b, 'c, H, I, OT, RT, S, TC> FridaInProcessExecutor<'a, 'b, 'c, H, I, OT, RT, S, TC>
where
    RT: FridaRuntimeTuple,
{
    /// Creates a new [`FridaInProcessExecutor`].
    pub fn with_target_bytes_converter(
        gum: &'a Gum,
        base: InProcessExecutor<'a, H, I, OT, S>,
        helper: &'c mut FridaInstrumentationHelper<'b, RT>,
        thread_id: Option<u32>,
        target_bytes_converter: TC,
    ) -> Self {
        let mut stalker = Stalker::new(gum);
        // Include the current module (the fuzzer) in stalked ranges. We clone the ranges so that
        // we don't add it to the INSTRUMENTED ranges.
        let mut ranges = helper.ranges().clone();
        for module in frida_gum::Module::obtain(gum).enumerate_modules() {
            if module.base_address < Self::with_target_bytes_converter as usize
                && (Self::with_target_bytes_converter as usize as u64)
                    < module.base_address as u64 + module.size as u64
            {
                ranges.insert(
                    module.base_address as u64..(module.base_address as u64 + module.size as u64),
                    (0xffff, "fuzzer".to_string()),
                );
                break;
            }
        }

        log::info!("disable_excludes: {:}", helper.disable_excludes);
        if !helper.disable_excludes {
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
impl<'a, 'b, 'c, H, I, OT, RT, S, TC> HasInProcessHooks<I, S>
    for FridaInProcessExecutor<'a, 'b, 'c, H, I, OT, RT, S, TC>
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
