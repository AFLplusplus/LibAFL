//! The in-process executor signal handling code for unix

use core::{ffi::c_void, sync::atomic::AtomicPtr};

use libafl_bolts::{
    os::unix_signals::{setup_signal_handler, Handler, Signal},
    Error,
};
use libc::{siginfo_t, ucontext_t};

use crate::executors::hooks::inprocess::InProcessHookInstaller;

pub struct UnixTimeoutHandler {
    callback: unsafe fn((Signal, &mut siginfo_t, Option<&mut ucontext_t>)),
}

static TIMEOUT_CALLBACK: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

impl Handler for UnixTimeoutHandler {
    fn handle(&mut self, signal: Signal, info: &mut siginfo_t, context: Option<&mut ucontext_t>) {
        (self.callback)((signal, info, context))
    }

    fn signals(&self) -> &'static [Signal] {
        static TIMEOUT_SIGNALS: [Signal; 1] = [Signal::SigAlarm];
        TIMEOUT_SIGNALS.as_slice()
    }
}

pub struct UnixTimeoutInstaller;

static TIMEOUT_HANDLER: AtomicPtr<UnixTimeoutHandler> = AtomicPtr::new(core::ptr::null_mut());

impl InProcessHookInstaller for UnixTimeoutInstaller {
    type Extra = (Signal, &mut siginfo_t, Option<&mut ucontext_t>);

    fn install(callback: unsafe fn(Self::Extra)) -> Result<(), Error> {
        let handler = Box::leak(Box::new())
        setup_signal_handler()
    }

    fn uninstall() -> Result<(), Error> {
        // it is unsafe to uninstall the pointer, as, once installed, we 
    }
}

/// Crash-Handler for in-process fuzzing.
/// Will be used for signal handling.
/// It will store the current State to shmem, then exit.
///
/// # Safety
/// Well, signal handling is not safe
#[allow(clippy::too_many_lines)]
#[allow(clippy::needless_pass_by_value)]
pub unsafe fn inproc_crash_handler<E, EM, I, S, Z>(
    signal: Signal,
    _info: &mut siginfo_t,
    context: Option<&mut ucontext_t>,
    data: &mut InProcessExecutorHandlerData,
) where
    E: HasObservers,
    EM: EventFirer<I, S> + EventRestarter<S>,
    S: HasExecutions + HasSolutions + HasCorpus,
    Z: HasObjective + HasScheduler + ExecutionProcessor<EM, I, E::Observers, S>,
    Z::Objective: Feedback<EM, I, E::Observers, S>,
{
    #[cfg(all(target_os = "android", target_arch = "aarch64"))]
    let context = context.map(|p| {
        &mut *(((core::ptr::from_mut(p) as *mut libc::c_void as usize) + 128) as *mut libc::c_void
            as *mut ucontext_t)
    });

    log::error!("Crashed with {signal}");
    if data.is_valid() {
        let executor = data.executor_mut::<E>();
        // disarms timeout in case of timeout
        let state = data.state_mut::<S>();
        let event_mgr = data.event_mgr_mut::<EM>();
        let fuzzer = data.fuzzer_mut::<Z>();
        let input = data.take_current_input::<I>();

        log::error!("Child crashed!");

        {
            let mut bsod = Vec::new();
            {
                let mut writer = std::io::BufWriter::new(&mut bsod);
                let _ = writeln!(writer, "input: {:?}", input.generate_name(None));
                let bsod = libafl_bolts::minibsod::generate_minibsod(
                    &mut writer,
                    signal,
                    _info,
                    context.as_deref(),
                );
                if bsod.is_err() {
                    log::error!("generate_minibsod failed");
                }
                let _ = writer.flush();
            }
            if let Ok(r) = std::str::from_utf8(&bsod) {
                log::error!("{}", r);
            }
        }

        run_observers_and_save_state::<E, EM, I, S, Z>(
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

            {
                let mut bsod = Vec::new();
                {
                    let mut writer = std::io::BufWriter::new(&mut bsod);
                    let bsod = libafl_bolts::minibsod::generate_minibsod(
                        &mut writer,
                        signal,
                        _info,
                        context.as_deref(),
                    );
                    if bsod.is_err() {
                        log::error!("generate_minibsod failed");
                    }
                    let _ = writer.flush();
                }
                if let Ok(r) = std::str::from_utf8(&bsod) {
                    log::error!("{}", r);
                }
            }
        }

        {
            log::error!("Type QUIT to restart the child");
            let mut line = String::new();
            while line.trim() != "QUIT" {
                let _ = std::io::stdin().read_line(&mut line);
            }
        }

        // TODO tell the parent to not restart
    }

    libc::_exit(128 + (signal as i32));
}
