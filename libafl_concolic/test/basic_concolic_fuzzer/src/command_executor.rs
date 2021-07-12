use std::{
    io::Write,
    process::{Child, Command, Stdio},
};

use libafl::{
    inputs::{HasTargetBytes, Input},
    Error,
};

use self::generic::CommandConfigurator;

#[derive(Default)]
pub struct MyCommandConfigurator;

impl<EM, I, S, Z> CommandConfigurator<EM, I, S, Z> for MyCommandConfigurator
where
    I: HasTargetBytes + Input,
{
    fn spawn_child(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<Child, Error> {
        let mut command = Command::new("../if");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let child = command.spawn().expect("failed to start process");
        let mut stdin = child.stdin.as_ref().unwrap();
        stdin.write_all(input.target_bytes().as_slice())?;
        Ok(child)
    }
}

pub mod generic {
    use std::{
        marker::PhantomData, os::unix::prelude::ExitStatusExt, process::Child, time::Duration,
    };

    use libafl::{
        executors::{Executor, ExitKind, HasObservers},
        inputs::Input,
        observers::ObserversTuple,
        Error,
    };
    use wait_timeout::ChildExt;

    pub struct CommandExecutor<EM, I, S, Z, T, OT>
    where
        I: Input,
        T: CommandConfigurator<EM, I, S, Z>,
        OT: ObserversTuple<I, S>,
    {
        inner: T,
        observers: OT,
        phantom: PhantomData<(EM, I, S, Z)>,
    }

    impl<EM, I, S, Z, T, OT> Executor<EM, I, S, Z> for CommandExecutor<EM, I, S, Z, T, OT>
    where
        I: Input,
        T: CommandConfigurator<EM, I, S, Z>,
        OT: ObserversTuple<I, S>,
    {
        fn run_target(
            &mut self,
            _fuzzer: &mut Z,
            _state: &mut S,
            _mgr: &mut EM,
            input: &I,
        ) -> Result<ExitKind, Error> {
            let mut child = self.inner.spawn_child(_fuzzer, _state, _mgr, input)?;

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
                    drop(child.kill());
                    // finally, try to wait to properly clean up system ressources.
                    drop(child.wait());
                    Ok(ExitKind::Timeout)
                }
            }
        }
    }

    impl<EM, I, S, Z, T, OT> HasObservers<I, OT, S> for CommandExecutor<EM, I, S, Z, T, OT>
    where
        I: Input,
        OT: ObserversTuple<I, S>,
        T: CommandConfigurator<EM, I, S, Z>,
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

    pub trait CommandConfigurator<EM, I: Input, S, Z>: Sized {
        fn spawn_child(
            &mut self,
            fuzzer: &mut Z,
            state: &mut S,
            mgr: &mut EM,
            input: &I,
        ) -> Result<Child, Error>;

        fn into_executor<OT>(self, observers: OT) -> CommandExecutor<EM, I, S, Z, Self, OT>
        where
            OT: ObserversTuple<I, S>,
        {
            CommandExecutor {
                inner: self,
                observers,
                phantom: PhantomData,
            }
        }
    }
}
