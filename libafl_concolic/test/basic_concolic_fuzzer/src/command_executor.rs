use std::{
    io::Write,
    marker::PhantomData,
    os::unix::prelude::ExitStatusExt,
    process::{Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use libafl::{
    executors::{Executor, ExitKind, HasExecHooksTuple, HasObservers, HasObserversHooks},
    inputs::{HasTargetBytes, Input},
    observers::ObserversTuple,
};

impl<I, OT, S> HasObservers<OT> for CommandExecutor<I, OT, S>
where
    I: Input,
    OT: ObserversTuple,
{
    #[inline]
    fn observers(&self) -> &OT {
        &self.observers
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}

impl<EM, I, OT, S, Z> HasObserversHooks<EM, I, OT, S, Z> for CommandExecutor<I, OT, S>
where
    I: Input,
    OT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
{
}

pub struct CommandExecutor<I, OT, S>
where
    I: Input,
    OT: ObserversTuple,
{
    /// The observers, observing each run
    observers: OT,
    phantom: PhantomData<(I, S)>,
}

impl<I: Input, OT: ObserversTuple, S> CommandExecutor<I, OT, S> {
    pub fn from_observers(observers: OT) -> Self {
        Self {
            observers,
            phantom: PhantomData,
        }
    }
}

impl<EM, I: HasTargetBytes + Input, S, Z, OT: ObserversTuple> Executor<EM, I, S, Z>
    for CommandExecutor<I, OT, S>
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, libafl::Error> {
        let mut command = Command::new("../if");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let start_time = Instant::now();
        let mut child = command.spawn().expect("failed to start process");
        let mut stdin = child.stdin.as_ref().unwrap();
        stdin.write_all(input.target_bytes().as_slice())?;

        loop {
            match child.try_wait().expect("waiting on child failed") {
                Some(exit_status) => {
                    if let Some(signal) = exit_status.signal() {
                        // for reference: https://www.man7.org/linux/man-pages/man7/signal.7.html
                        match signal {
                    9 /* SIGKILL */ => {
                        // we assume the child was killed due to OOM
                        return Ok(ExitKind::Oom);
                    }
                    _ => {return Ok(ExitKind::Crash);}
                }
                    } else {
                        return Ok(ExitKind::Ok);
                    }
                }
                None => {
                    if start_time.elapsed() > Duration::from_secs(5) {
                        return Ok(ExitKind::Timeout);
                    }
                    sleep(Duration::from_millis(1));
                }
            }
        }
    }
}
