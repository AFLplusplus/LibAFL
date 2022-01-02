//! The command executor executes a sub program for each run
use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

#[cfg(feature = "std")]
use std::process::Child;

#[cfg(feature = "std")]
use crate::{executors::HasObservers, inputs::Input, observers::ObserversTuple, Error};

#[cfg(all(feature = "std", unix))]
use crate::executors::{Executor, ExitKind};

#[cfg(all(feature = "std", unix))]
use std::time::Duration;

/// A `CommandExecutor` is a wrapper around [`std::process::Command`] to execute a target as a child process.
/// Construct a `CommandExecutor` by implementing [`CommandConfigurator`] for a type of your choice and calling [`CommandConfigurator::into_executor`] on it.
pub struct CommandExecutor<EM, I, S, Z, T: Debug, OT: Debug> {
    inner: T,
    /// [`crate::observers::Observer`]s for this executor
    observers: OT,
    phantom: PhantomData<(EM, I, S, Z)>,
}

impl<EM, I, S, Z, T: Debug, OT: Debug> Debug for CommandExecutor<EM, I, S, Z, T, OT> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandExecutor")
            .field("inner", &self.inner)
            .field("observers", &self.observers)
            .finish()
    }
}

impl<EM, I, S, Z, T: Debug, OT: Debug> CommandExecutor<EM, I, S, Z, T, OT> {
    /// Accesses the inner value
    pub fn inner(&mut self) -> &mut T {
        &mut self.inner
    }
}

// this only works on unix because of the reliance on checking the process signal for detecting OOM
#[cfg(all(feature = "std", unix))]
impl<EM, I, S, Z, T: Debug, OT: Debug> Executor<EM, I, S, Z> for CommandExecutor<EM, I, S, Z, T, OT>
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
        use std::os::unix::prelude::ExitStatusExt;
        use wait_timeout::ChildExt;

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
                // finally, try to wait to properly clean up system resources.
                drop(child.wait());
                Ok(ExitKind::Timeout)
            }
        }
    }
}

#[cfg(all(feature = "std", unix))]
impl<EM, I, S, Z, T: Debug, OT: Debug> HasObservers<I, OT, S>
    for CommandExecutor<EM, I, S, Z, T, OT>
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

/// A `CommandConfigurator` takes care of creating and spawning a [`std::process::Command`] for the [`CommandExecutor`].
/// # Example
/// ```
/// use std::{io::Write, process::{Stdio, Command, Child}};
/// use libafl::{Error, inputs::{Input, HasTargetBytes}, executors::{Executor, command::CommandConfigurator}};
/// struct MyExecutor;
///
/// impl<EM, I: Input + HasTargetBytes, S, Z> CommandConfigurator<EM, I, S, Z> for MyExecutor {
///     fn spawn_child(
///        &mut self,
///        fuzzer: &mut Z,
///        state: &mut S,
///        mgr: &mut EM,
///        input: &I,
///     ) -> Result<Child, Error> {
///         let mut command = Command::new("../if");
///         command
///             .stdin(Stdio::piped())
///             .stdout(Stdio::null())
///             .stderr(Stdio::null());
///
///         let child = command.spawn().expect("failed to start process");
///         let mut stdin = child.stdin.as_ref().unwrap();
///         stdin.write_all(input.target_bytes().as_slice())?;
///         Ok(child)
///     }
/// }
///
/// fn make_executor<EM, I: Input + HasTargetBytes, S, Z>() -> impl Executor<EM, I, S, Z> {
///     MyExecutor.into_executor(())
/// }
/// ```
#[cfg(all(feature = "std", unix))]
pub trait CommandConfigurator<EM, I: Input, S, Z>: Sized + Debug {
    /// Spawns a new process with the given configuration.
    fn spawn_child(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<Child, Error>;

    /// Create an `Executor` from this `CommandConfigurator`.
    fn into_executor<OT: Debug>(self, observers: OT) -> CommandExecutor<EM, I, S, Z, Self, OT>
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
