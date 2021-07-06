use std::{
    io::Write,
    marker::PhantomData,
    os::unix::prelude::ExitStatusExt,
    process::{Command, Stdio},
    time::Duration,
};

use libafl::{
    executors::{Executor, ExitKind, HasExecHooksTuple, HasObservers, HasObserversHooks},
    inputs::{HasTargetBytes, Input},
    observers::ObserversTuple,
};
use wait_timeout::ChildExt;

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
    pub fn new(observers: OT) -> Self {
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

        let mut child = command.spawn().expect("failed to start process");
        let mut stdin = child.stdin.as_ref().unwrap();
        stdin.write_all(input.target_bytes().as_slice())?;

        match child
            .wait_timeout(Duration::from_secs(5))
            .expect("waiting on child failed")
            .map(|status| status.signal())
        {
            // for reference: https://www.man7.org/linux/man-pages/man7/signal.7.html
            Some(Some(9)) => Ok(ExitKind::Oom),
            Some(Some(_)) => Ok(ExitKind::Crash),
            Some(None) => Ok(ExitKind::Ok),
            None => {
                // if this fails, there is not much we can do. let's hope it failed because the process finished
                // in the meantime.
                let _ = child.kill();
                // finally, try to wait to properly clean up system ressources.
                let _ = child.wait();
                Ok(ExitKind::Timeout)
            }
        }
    }
}
