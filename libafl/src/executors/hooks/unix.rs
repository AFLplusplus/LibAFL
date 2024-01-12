/// The inprocess executor singal handling code for unix
#[cfg(unix)]
pub mod unix_signal_handler {
    use alloc::vec::Vec;
    #[cfg(feature = "std")]
    use alloc::{boxed::Box, string::String};
    use core::mem::transmute;
    #[cfg(feature = "std")]
    use std::{io::Write, panic};

    use libafl_bolts::os::unix_signals::{ucontext_t, Handler, Signal};
    use libc::siginfo_t;

    #[cfg(feature = "std")]
    use crate::inputs::Input;
    use crate::{
        events::{EventFirer, EventRestarter},
        executors::{
            common_signals,
            hooks::inprocess::{InProcessExecutorHandlerData, GLOBAL_STATE},
            inprocess::run_observers_and_save_state,
            Executor, ExitKind, HasObservers,
        },
        feedbacks::Feedback,
        fuzzer::HasObjective,
        inputs::UsesInput,
        state::{HasCorpus, HasExecutions, HasSolutions},
    };

    pub(crate) type HandlerFuncPtr = unsafe fn(
        Signal,
        &mut siginfo_t,
        Option<&mut ucontext_t>,
        data: &mut InProcessExecutorHandlerData,
    );

    /// A handler that does nothing.
    /*pub fn nop_handler(
        _signal: Signal,
        _info: &mut siginfo_t,
        _context: Option<&mut ucontext_t>,
        _data: &mut InProcessExecutorHandlerData,
    ) {
    }*/

    #[cfg(unix)]
    impl Handler for InProcessExecutorHandlerData {
        fn handle(
            &mut self,
            signal: Signal,
            info: &mut siginfo_t,
            context: Option<&mut ucontext_t>,
        ) {
            unsafe {
                let data = &mut GLOBAL_STATE;
                let in_handler = data.set_in_handler(true);
                match signal {
                    Signal::SigUser2 | Signal::SigAlarm => {
                        if !data.timeout_handler.is_null() {
                            let func: HandlerFuncPtr = transmute(data.timeout_handler);
                            (func)(signal, info, context, data);
                        }
                    }
                    _ => {
                        if !data.crash_handler.is_null() {
                            let func: HandlerFuncPtr = transmute(data.crash_handler);
                            (func)(signal, info, context, data);
                        }
                    }
                }
                data.set_in_handler(in_handler);
            }
        }

        fn signals(&self) -> Vec<Signal> {
            common_signals()
        }
    }

    /// invokes the `post_exec` hook on all observer in case of panic
    #[cfg(feature = "std")]
    pub fn setup_panic_hook<E, EM, OF, Z>()
    where
        E: HasObservers,
        EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
        OF: Feedback<E::State>,
        E::State: HasExecutions + HasSolutions + HasCorpus,
        Z: HasObjective<Objective = OF, State = E::State>,
    {
        let old_hook = panic::take_hook();
        panic::set_hook(Box::new(move |panic_info| {
            old_hook(panic_info);
            let data = unsafe { &mut GLOBAL_STATE };
            let in_handler = data.set_in_handler(true);
            if data.is_valid() {
                // We are fuzzing!
                let executor = data.executor_mut::<E>();
                let state = data.state_mut::<E::State>();
                let input = data.take_current_input::<<E::State as UsesInput>::Input>();
                let fuzzer = data.fuzzer_mut::<Z>();
                let event_mgr = data.event_mgr_mut::<EM>();

                run_observers_and_save_state::<E, EM, OF, Z>(
                    executor,
                    state,
                    input,
                    fuzzer,
                    event_mgr,
                    ExitKind::Crash,
                );

                unsafe {
                    libc::_exit(128 + 6);
                } // SIGABRT exit code
            }
            data.set_in_handler(in_handler);
        }));
    }

    /// Timeout-Handler for in-process fuzzing.
    /// It will store the current State to shmem, then exit.
    ///
    /// # Safety
    /// Well, signal handling is not safe
    #[cfg(unix)]
    pub unsafe fn inproc_timeout_handler<E, EM, OF, Z>(
        _signal: Signal,
        _info: &mut siginfo_t,
        _context: &Option<&mut ucontext_t>,
        data: &mut InProcessExecutorHandlerData,
    ) where
        E: HasObservers,
        EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
        OF: Feedback<E::State>,
        E::State: HasExecutions + HasSolutions + HasCorpus,
        Z: HasObjective<Objective = OF, State = E::State>,
    {
        if !data.timeout_executor_ptr.is_null()
            && data.timeout_executor_mut::<E>().handle_timeout(data)
        {
            return;
        }

        if !data.is_valid() {
            log::warn!("TIMEOUT or SIGUSR2 happened, but currently not fuzzing.");
            return;
        }

        let executor = data.executor_mut::<E>();
        let state = data.state_mut::<E::State>();
        let event_mgr = data.event_mgr_mut::<EM>();
        let fuzzer = data.fuzzer_mut::<Z>();
        let input = data.take_current_input::<<E::State as UsesInput>::Input>();

        log::error!("Timeout in fuzz run.");

        run_observers_and_save_state::<E, EM, OF, Z>(
            executor,
            state,
            input,
            fuzzer,
            event_mgr,
            ExitKind::Timeout,
        );

        libc::_exit(55);
    }

    /// Crash-Handler for in-process fuzzing.
    /// Will be used for signal handling.
    /// It will store the current State to shmem, then exit.
    ///
    /// # Safety
    /// Well, signal handling is not safe
    #[allow(clippy::too_many_lines)]
    pub unsafe fn inproc_crash_handler<E, EM, OF, Z>(
        signal: Signal,
        _info: &mut siginfo_t,
        _context: &Option<&mut ucontext_t>,
        data: &mut InProcessExecutorHandlerData,
    ) where
        E: Executor<EM, Z> + HasObservers,
        EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
        OF: Feedback<E::State>,
        E::State: HasExecutions + HasSolutions + HasCorpus,
        Z: HasObjective<Objective = OF, State = E::State>,
    {
        #[cfg(all(target_os = "android", target_arch = "aarch64"))]
        let _context = _context.as_ref().map(|p| {
            &mut *(((p as *mut _ as *mut libc::c_void as usize) + 128) as *mut libc::c_void
                as *mut ucontext_t)
        });

        log::error!("Crashed with {signal}");
        if data.is_valid() {
            let executor = data.executor_mut::<E>();
            // disarms timeout in case of TimeoutExecutor
            executor.post_run_reset();
            let state = data.state_mut::<E::State>();
            let event_mgr = data.event_mgr_mut::<EM>();
            let fuzzer = data.fuzzer_mut::<Z>();
            let input = data.take_current_input::<<E::State as UsesInput>::Input>();

            log::error!("Child crashed!");

            #[cfg(all(feature = "std", unix))]
            {
                let mut bsod = Vec::new();
                {
                    let mut writer = std::io::BufWriter::new(&mut bsod);
                    writeln!(writer, "input: {:?}", input.generate_name(0)).unwrap();
                    libafl_bolts::minibsod::generate_minibsod(
                        &mut writer,
                        signal,
                        _info,
                        _context.as_deref(),
                    )
                    .unwrap();
                    writer.flush().unwrap();
                }
                log::error!("{}", std::str::from_utf8(&bsod).unwrap());
            }

            run_observers_and_save_state::<E, EM, OF, Z>(
                executor,
                state,
                input,
                fuzzer,
                event_mgr,
                ExitKind::Crash,
            );
        } else {
            {
                log::error!("Double crash\n");
                #[cfg(target_os = "android")]
                let si_addr = (_info._pad[0] as i64) | ((_info._pad[1] as i64) << 32);
                #[cfg(not(target_os = "android"))]
                let si_addr = { _info.si_addr() as usize };

                log::error!(
                    "We crashed at addr 0x{si_addr:x}, but are not in the target... Bug in the fuzzer? Exiting."
                );

                #[cfg(all(feature = "std", unix))]
                {
                    let mut bsod = Vec::new();
                    {
                        let mut writer = std::io::BufWriter::new(&mut bsod);
                        libafl_bolts::minibsod::generate_minibsod(
                            &mut writer,
                            signal,
                            _info,
                            _context.as_deref(),
                        )
                        .unwrap();
                        writer.flush().unwrap();
                    }
                    log::error!("{}", std::str::from_utf8(&bsod).unwrap());
                }
            }

            #[cfg(feature = "std")]
            {
                log::error!("Type QUIT to restart the child");
                let mut line = String::new();
                while line.trim() != "QUIT" {
                    std::io::stdin().read_line(&mut line).unwrap();
                }
            }

            // TODO tell the parent to not restart
        }

        libc::_exit(128 + (signal as i32));
    }
}
