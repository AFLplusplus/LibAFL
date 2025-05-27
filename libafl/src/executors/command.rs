//! The command executor executes a sub program for each run
#[cfg(all(feature = "intel_pt", target_os = "linux"))]
use alloc::ffi::CString;
#[cfg(all(feature = "intel_pt", target_os = "linux"))]
use alloc::vec::Vec;
#[cfg(all(feature = "intel_pt", target_os = "linux"))]
use core::ffi::CStr;
use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    ops::IndexMut,
    time::Duration,
};
#[cfg(all(feature = "intel_pt", target_os = "linux"))]
use std::os::fd::AsRawFd;
use std::{
    ffi::OsStr,
    io::{Read, Write},
    os::{fd::RawFd, unix::ffi::OsStrExt},
    process::{Child, Command, Stdio},
};

use libafl_bolts::{
    AsSlice, InputLocation, StdTargetArgs, StdTargetArgsInner,
    tuples::{Handle, MatchName, MatchNameRef, RefIndexable},
};
#[cfg(all(feature = "intel_pt", target_os = "linux"))]
use libafl_bolts::{core_affinity::CoreId, os::dup2};
#[cfg(all(feature = "intel_pt", target_os = "linux"))]
use libc::STDIN_FILENO;
#[cfg(target_os = "linux")]
use nix::{
    errno::Errno,
    sys::{
        ptrace,
        signal::Signal,
        wait::WaitStatus,
        wait::{
            WaitPidFlag,
            WaitStatus::{Exited, PtraceEvent, Signaled, Stopped},
            waitpid,
        },
    },
    unistd::Pid,
};
#[cfg(all(feature = "intel_pt", target_os = "linux"))]
use typed_builder::TypedBuilder;

#[cfg(all(target_family = "unix", feature = "fork"))]
use super::forkserver::ConfigTarget;
use super::{HasTimeout, StdChildArgs, StdChildArgsInner};
#[cfg(target_os = "linux")]
use crate::executors::hooks::ExecutorHooksTuple;
use crate::{
    Error,
    executors::{Executor, ExitKind, HasObservers},
    inputs::HasTargetBytes,
    observers::{ObserversTuple, StdErrObserver, StdOutObserver},
    state::HasExecutions,
};

/// How do we capture stdout/stderr. Not intended for public use.
#[derive(Debug, Default)]
#[allow(dead_code)]
enum StdCommandCaptureMethod {
    Fd(RawFd),
    #[default]
    Pipe,
}

impl StdCommandCaptureMethod {
    fn pipe_capture(cmd: &mut Command, stdout: bool) {
        if stdout {
            cmd.stdout(Stdio::piped());
        } else {
            cmd.stderr(Stdio::piped());
        }
    }

    fn pre_capture(&self, cmd: &mut Command, stdout: bool) {
        #[cfg(feature = "fork")]
        {
            if let Self::Fd(old) = self {
                // Safety
                // We set up the file desciptors we assume to be valid and not closed (yet)
                unsafe {
                    if stdout {
                        cmd.setdup2(*old, libc::STDOUT_FILENO);
                        cmd.stdout(Stdio::null());
                    } else {
                        cmd.setdup2(*old, libc::STDERR_FILENO);
                        cmd.stderr(Stdio::null());
                    }
                }
            } else {
                Self::pipe_capture(cmd, stdout);
            }
        }

        #[cfg(not(feature = "fork"))]
        Self::pipe_capture(cmd, stdout);
    }
}

/// A simple Configurator that takes the most common parameters
/// Writes the input either to stdio or to a file
/// Use [`CommandExecutor::builder()`] to use this configurator.
#[derive(Debug)]
pub struct StdCommandConfigurator {
    /// If set to true, the child output will remain visible
    /// By default, the child output is hidden to increase execution speed
    debug_child: bool,
    stdout_cap: Option<StdCommandCaptureMethod>,
    stderr_cap: Option<StdCommandCaptureMethod>,
    timeout: Duration,
    /// true: input gets delivered via stdink
    input_location: InputLocation,
    /// The Command to execute
    command: Command,
}

impl<I> CommandConfigurator<I> for StdCommandConfigurator
where
    I: HasTargetBytes,
{
    fn spawn_child(&mut self, input: &I) -> Result<Child, Error> {
        let mut cmd = Command::new(self.command.get_program());
        match &mut self.input_location {
            InputLocation::Arg { argnum } => {
                let args = self.command.get_args();

                if self.debug_child {
                    cmd.stdout(Stdio::inherit());
                } else if let Some(cap) = &self.stdout_cap {
                    cap.pre_capture(&mut cmd, true);
                } else {
                    cmd.stdout(Stdio::null());
                }

                if self.debug_child {
                    cmd.stderr(Stdio::inherit());
                } else if let Some(cap) = &self.stderr_cap {
                    cap.pre_capture(&mut cmd, false);
                } else {
                    cmd.stderr(Stdio::null());
                }

                for (i, arg) in args.enumerate() {
                    if i == *argnum {
                        debug_assert_eq!(arg, "PLACEHOLDER");
                        #[cfg(unix)]
                        cmd.arg(OsStr::from_bytes(input.target_bytes().as_slice()));
                        // There is an issue here that the chars on Windows are 16 bit wide.
                        // I can't really test it. Please open a PR if this goes wrong.
                        #[cfg(not(unix))]
                        cmd.arg(OsString::from_vec(input.target_bytes().as_vec()));
                    } else {
                        cmd.arg(arg);
                    }
                }
                cmd.envs(
                    self.command
                        .get_envs()
                        .filter_map(|(key, value)| value.map(|value| (key, value))),
                );
                if let Some(cwd) = self.command.get_current_dir() {
                    cmd.current_dir(cwd);
                }
                Ok(cmd.spawn()?)
            }
            InputLocation::StdIn { input_file: _ } => {
                let mut handle = self.command.stdin(Stdio::piped()).spawn()?;
                let mut stdin = handle.stdin.take().unwrap();
                match stdin.write_all(input.target_bytes().as_slice()) {
                    Err(err) => {
                        if err.kind() != std::io::ErrorKind::BrokenPipe {
                            return Err(err.into());
                        }
                    }
                    _ => {
                        if let Err(err) = stdin.flush() {
                            if err.kind() != std::io::ErrorKind::BrokenPipe {
                                return Err(err.into());
                            }
                        }
                    }
                }
                drop(stdin);
                Ok(handle)
            }
            InputLocation::File { out_file } => {
                out_file.write_buf(input.target_bytes().as_slice())?;
                Ok(self.command.spawn()?)
            }
        }
    }

    fn exec_timeout(&self) -> Duration {
        self.timeout
    }
    fn exec_timeout_mut(&mut self) -> &mut Duration {
        &mut self.timeout
    }
}

/// Linux specific [`CommandConfigurator`] that leverages `ptrace`
///
/// This configurator was primarly developed to be used in conjunction with
/// [`crate::executors::hooks::intel_pt::IntelPTHook`]
#[cfg(all(feature = "intel_pt", target_os = "linux"))]
#[derive(Debug, Clone, PartialEq, Eq, TypedBuilder)]
pub struct PTraceCommandConfigurator {
    #[builder(setter(into))]
    path: CString,
    #[builder(default)]
    args: Vec<CString>,
    #[builder(default)]
    env: Vec<CString>,
    #[builder(default)]
    input_location: InputLocation,
    #[builder(default, setter(strip_option))]
    cpu: Option<CoreId>,
    #[builder(default = 5 * 60, setter(transform = |t: Duration| t.as_secs() as u32))]
    timeout: u32,
}

#[cfg(all(feature = "intel_pt", target_os = "linux"))]
impl<I> CommandConfigurator<I, Pid> for PTraceCommandConfigurator
where
    I: HasTargetBytes,
{
    fn spawn_child(&mut self, input: &I) -> Result<Pid, Error> {
        use nix::{
            sys::{
                personality, ptrace,
                signal::{Signal, raise},
            },
            unistd::{ForkResult, alarm, execve, fork, pipe, write},
        };

        match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => Ok(child),
            Ok(ForkResult::Child) => {
                if let Some(c) = self.cpu {
                    c.set_affinity_forced().unwrap();
                }

                // Disable Address Space Layout Randomization (ASLR) for consistent memory
                // addresses between executions
                let pers = personality::get().unwrap();
                personality::set(pers | personality::Persona::ADDR_NO_RANDOMIZE).unwrap();

                match &mut self.input_location {
                    InputLocation::Arg { argnum } => {
                        // self.args[argnum] will be overwritten if already present.
                        assert!(
                            *argnum <= self.args.len(),
                            "If you want to fuzz arg {argnum}, you have to specify the other {argnum} (static) args."
                        );
                        let terminated_input = [&input.target_bytes() as &[u8], &[0]].concat();
                        let cstring_input =
                            CString::from(CStr::from_bytes_until_nul(&terminated_input).unwrap());
                        if *argnum == self.args.len() {
                            self.args.push(cstring_input);
                        } else {
                            self.args[*argnum] = cstring_input;
                        }
                    }
                    InputLocation::StdIn { input_file: _ } => {
                        let (pipe_read, pipe_write) = pipe().unwrap();
                        write(pipe_write, &input.target_bytes()).unwrap();
                        // # Safety
                        // We replace the Stdin fileno. Typical Unix stuff.
                        unsafe { dup2(pipe_read.as_raw_fd(), STDIN_FILENO)? };
                    }
                    InputLocation::File { out_file } => {
                        out_file.write_buf(input.target_bytes().as_slice()).unwrap();
                    }
                }

                ptrace::traceme().unwrap();
                // After this STOP, the process is traced with PTrace (no hooks yet)
                raise(Signal::SIGSTOP).unwrap();

                alarm::set(self.timeout);

                // Just before this returns, hooks pre_execs are called
                execve(&self.path, &self.args, &self.env).unwrap();
                unreachable!("execve returns only on error and its result is unwrapped");
            }
            Err(e) => Err(Error::unknown(format!("Fork failed: {e}"))),
        }
    }

    fn exec_timeout(&self) -> Duration {
        Duration::from_secs(u64::from(self.timeout))
    }

    /// Use [`PTraceCommandConfigurator::builder().timeout`] instead
    fn exec_timeout_mut(&mut self) -> &mut Duration {
        unimplemented!("Use [`PTraceCommandConfigurator::builder().timeout`] instead")
    }
}

/// A `CommandExecutor` is a wrapper around [`Command`] to execute a target as a child process.
///
/// Construct a `CommandExecutor` by implementing [`CommandConfigurator`] for a type of your choice and calling [`CommandConfigurator::into_executor`] on it.
/// Instead, you can use [`CommandExecutor::builder()`] to construct a [`CommandExecutor`] backed by a [`StdCommandConfigurator`].
pub struct CommandExecutor<I, OT, S, T, HT = (), C = Child> {
    /// The wrapped command configurer
    configurer: T,
    /// The observers used by this executor
    observers: OT,
    stdout_observer: Option<Handle<StdOutObserver>>,
    stderr_observer: Option<Handle<StdErrObserver>>,
    hooks: HT,
    phantom: PhantomData<(C, I, S)>,
}

impl CommandExecutor<(), (), (), ()> {
    /// Creates a builder for a new [`CommandExecutor`],
    /// backed by a [`StdCommandConfigurator`]
    /// This is usually the easiest way to construct a [`CommandExecutor`].
    ///
    /// It mimics the api of [`Command`], specifically, you will use
    /// `arg`, `args`, `env`, and so on.
    ///
    /// By default, input is read from stdin, unless you specify a different location using
    /// * `arg_input_arg` for input delivered _as_ a command line argument
    /// * `arg_input_file` for input via a file of a specific name
    /// * `arg_input_file_std` for a file with default name (at the right location in the arguments)
    #[must_use]
    pub fn builder() -> CommandExecutorBuilder {
        CommandExecutorBuilder::new()
    }
}

impl<I, OT, S, T, HT, C> Debug for CommandExecutor<I, OT, S, T, HT, C>
where
    T: Debug,
    OT: Debug,
    HT: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandExecutor")
            .field("inner", &self.configurer)
            .field("observers", &self.observers)
            .field("hooks", &self.hooks)
            .field("stdout_observer", &self.stdout_observer)
            .field("stderr_observer", &self.stderr_observer)
            .finish()
    }
}

impl<I, OT, S, T, HT, C> CommandExecutor<I, OT, S, T, HT, C> {
    /// Accesses the inner value
    pub fn inner(&mut self) -> &mut T {
        &mut self.configurer
    }
}

// this only works on unix because of the reliance on checking the process signal for detecting OOM
impl<I, OT, S, T> CommandExecutor<I, OT, S, T>
where
    S: HasExecutions,
    T: CommandConfigurator<I> + Debug,
    OT: ObserversTuple<I, S>,
{
    fn execute_input_with_command(&mut self, state: &mut S, input: &I) -> Result<ExitKind, Error> {
        use wait_timeout::ChildExt;

        self.observers_mut().pre_exec_all(state, input)?;
        *state.executions_mut() += 1;
        let mut child = self.configurer.spawn_child(input)?;

        let exit_kind = child
            .wait_timeout(self.configurer.exec_timeout())
            .expect("waiting on child failed")
            .map(|status| self.configurer.exit_kind_from_status(&status))
            .unwrap_or_else(|| {
                // if this fails, there is not much we can do. let's hope it failed because the process finished
                // in the meantime.
                drop(child.kill());
                // finally, try to wait to properly clean up system resources.
                drop(child.wait());
                ExitKind::Timeout
            });

        // Manualy update stdout/stderr here if we use piped implementation.
        // Reason of not putting into state and pass by post_exec_all is that
        // - Save extra at least two hashmap lookups since we already know the handle
        // - Doesn't pose HasNamedMetadata bound on S (note we might have many stdout/stderr observers)
        if let Some(mut stderr) = child.stderr {
            if let Some(stderr_handle) = self.stderr_observer.clone() {
                let mut buf = vec![];
                stderr.read_to_end(&mut buf)?;
                self.observers_mut().index_mut(&stderr_handle).observe(buf);
            }
        }

        if let Some(mut stdout) = child.stdout {
            if let Some(stdout_handle) = self.stdout_observer.clone() {
                let mut buf = vec![];
                stdout.read_to_end(&mut buf)?;
                self.observers_mut().index_mut(&stdout_handle).observe(buf);
            }
        }

        self.observers_mut()
            .post_exec_child_all(state, input, &exit_kind)?;
        Ok(exit_kind)
    }
}

impl<EM, I, OT, S, T, Z> Executor<EM, I, S, Z> for CommandExecutor<I, OT, S, T>
where
    S: HasExecutions,
    T: CommandConfigurator<I> + Debug,
    OT: MatchName + ObserversTuple<I, S>,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        self.execute_input_with_command(state, input)
    }
}

// this only works on unix because of the reliance on checking the process signal for detecting OOM
impl<I, OT, S, T> HasTimeout for CommandExecutor<I, OT, S, T>
where
    T: CommandConfigurator<I>,
{
    #[inline]
    fn timeout(&self) -> Duration {
        self.configurer.exec_timeout()
    }

    #[inline]
    fn set_timeout(&mut self, timeout: Duration) {
        *self.configurer.exec_timeout_mut() = timeout;
    }
}

#[cfg(target_os = "linux")]
impl<EM, I, OT, S, T, Z, HT> Executor<EM, I, S, Z> for CommandExecutor<I, OT, S, T, HT, Pid>
where
    HT: ExecutorHooksTuple<I, S>,
    OT: MatchName + ObserversTuple<I, S>,
    S: HasExecutions,
    T: CommandConfigurator<I, Pid> + Debug,
{
    /// Linux specific low level implementation, to directly handle `fork`, `exec` and use linux
    /// `ptrace`
    ///
    /// Hooks' `pre_exec` and observers' `pre_exec_child` are called with the child process stopped
    /// just before the `exec` return (after forking).
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        *state.executions_mut() += 1;

        let child = self.configurer.spawn_child(input)?;

        let wait_status = waitpid_filtered(child, Some(WaitPidFlag::WUNTRACED))?;
        if !matches!(wait_status, Stopped(c, Signal::SIGSTOP) if c == child) {
            return Err(Error::unknown(format!(
                "Unexpected state of child process {wait_status:?} (while waiting for SIGSTOP)"
            )));
        }

        let options = ptrace::Options::PTRACE_O_TRACEEXEC | ptrace::Options::PTRACE_O_EXITKILL;
        ptrace::setoptions(child, options)?;
        ptrace::cont(child, None)?;

        let wait_status = waitpid_filtered(child, None)?;
        if !matches!(wait_status, PtraceEvent(c, Signal::SIGTRAP, e)
            if c == child && e == (ptrace::Event::PTRACE_EVENT_EXEC as i32)
        ) {
            return Err(Error::unknown(format!(
                "Unexpected state of child process {wait_status:?} (while waiting for SIGTRAP PTRACE_EVENT_EXEC)"
            )));
        }

        self.observers.pre_exec_child_all(state, input)?;
        if *state.executions() == 1 {
            self.hooks.init_all(state);
        }
        self.hooks.pre_exec_all(state, input);

        // todo: it might be better to keep the target ptraced in case the target handles sigalarm,
        // breaking the libafl timeout
        ptrace::detach(child, None)?;
        let res = match waitpid(child, None)? {
            Exited(pid, 0) if pid == child => ExitKind::Ok,
            Exited(pid, _) if pid == child => ExitKind::Crash,
            Signaled(pid, Signal::SIGALRM, _has_coredump) if pid == child => ExitKind::Timeout,
            Signaled(pid, Signal::SIGABRT, _has_coredump) if pid == child => ExitKind::Crash,
            Signaled(pid, Signal::SIGKILL, _has_coredump) if pid == child => ExitKind::Oom,
            // Stopped(pid, Signal::SIGALRM) if pid == child => ExitKind::Timeout,
            // Stopped(pid, Signal::SIGABRT) if pid == child => ExitKind::Crash,
            // Stopped(pid, Signal::SIGKILL) if pid == child => ExitKind::Oom,
            s => {
                // TODO other cases?
                return Err(Error::unsupported(format!(
                    "Target program returned an unexpected state when waiting on it. {s:?} (waiting for pid {child})"
                )));
            }
        };

        self.hooks.post_exec_all(state, input);
        self.observers.post_exec_child_all(state, input, &res)?;
        Ok(res)
    }
}

impl<I, OT, S, T, HT, C> HasObservers for CommandExecutor<I, OT, S, T, HT, C>
where
    OT: ObserversTuple<I, S>,
{
    type Observers = OT;

    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}

/// The builder for a default [`CommandExecutor`] that should fit most use-cases.
#[derive(Debug, Clone)]
pub struct CommandExecutorBuilder {
    target_inner: StdTargetArgsInner,
    child_env_inner: StdChildArgsInner,
}

impl StdTargetArgs for CommandExecutorBuilder {
    fn inner(&self) -> &StdTargetArgsInner {
        &self.target_inner
    }

    fn inner_mut(&mut self) -> &mut StdTargetArgsInner {
        &mut self.target_inner
    }
}

impl StdChildArgs for CommandExecutorBuilder {
    fn inner(&self) -> &StdChildArgsInner {
        &self.child_env_inner
    }

    fn inner_mut(&mut self) -> &mut StdChildArgsInner {
        &mut self.child_env_inner
    }
}

impl Default for CommandExecutorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandExecutorBuilder {
    /// Create a new [`CommandExecutorBuilder`]
    #[must_use]
    fn new() -> CommandExecutorBuilder {
        CommandExecutorBuilder {
            target_inner: StdTargetArgsInner::default(),
            child_env_inner: StdChildArgsInner::default(),
        }
    }

    /// Builds the `CommandExecutor`
    pub fn build<I, OT, S>(
        &self,
        observers: OT,
    ) -> Result<CommandExecutor<I, OT, S, StdCommandConfigurator>, Error>
    where
        I: HasTargetBytes,
        OT: MatchName + ObserversTuple<I, S>,
    {
        let Some(program) = &self.target_inner.program else {
            return Err(Error::illegal_argument(
                "CommandExecutor::builder: no program set!",
            ));
        };

        let mut command = Command::new(program);
        match &self.target_inner.input_location {
            InputLocation::StdIn {
                input_file: out_file,
            } => {
                if out_file.is_some() {
                    return Err(Error::illegal_argument(
                        "Setting filename for CommandExecutor is not supported!",
                    ));
                }
                command.stdin(Stdio::piped());
            }
            InputLocation::File { .. } | InputLocation::Arg { .. } => {
                command.stdin(Stdio::null());
            }
        }
        command.args(&self.target_inner.arguments);
        command.envs(
            self.target_inner
                .envs
                .iter()
                .map(|(k, v)| (k.as_os_str(), v.as_os_str())),
        );
        if let Some(cwd) = &self.child_env_inner.current_directory {
            command.current_dir(cwd);
        }

        let stdout_cap = self.child_env_inner.stdout_observer.as_ref().map(|hdl| {
            observers
                .get(hdl)
                .as_ref()
                .expect("stdout observer not in observers tuple")
                .as_raw_fd()
                .map(StdCommandCaptureMethod::Fd)
                .unwrap_or_default()
        });

        let stderr_cap = self.child_env_inner.stderr_observer.as_ref().map(|hdl| {
            observers
                .get(hdl)
                .as_ref()
                .expect("stderr observer not in observers tuple")
                .as_raw_fd()
                .map(StdCommandCaptureMethod::Fd)
                .unwrap_or_default()
        });

        if self.child_env_inner.debug_child {
            command.stdout(Stdio::piped());
            command.stderr(Stdio::piped());
        } else {
            if let Some(cap) = &stdout_cap {
                cap.pre_capture(&mut command, true);
            } else {
                command.stdout(Stdio::null());
            }

            if let Some(cap) = &stderr_cap {
                cap.pre_capture(&mut command, false);
            } else {
                command.stderr(Stdio::null());
            }
        }

        if self.child_env_inner.stdout_observer.is_some() {
            command.stdout(Stdio::piped());
        }

        if self.child_env_inner.stderr_observer.is_some() {
            command.stderr(Stdio::piped());
        }

        if let Some(core) = self.child_env_inner.core {
            #[cfg(feature = "fork")]
            command.bind(core);

            #[cfg(not(feature = "fork"))]
            return Err(Error::illegal_argument(format!(
                "Your host doesn't support fork and thus libafl can not bind to core {:?} right after children get spawned",
                core
            )));
        }

        let configurator = StdCommandConfigurator {
            debug_child: self.child_env_inner.debug_child,
            stdout_cap,
            stderr_cap,
            input_location: self.target_inner.input_location.clone(),
            timeout: self.child_env_inner.timeout,
            command,
        };

        Ok(
            <StdCommandConfigurator as CommandConfigurator<I>>::into_executor::<OT, S>(
                configurator,
                observers,
                self.child_env_inner.stdout_observer.clone(),
                self.child_env_inner.stderr_observer.clone(),
            ),
        )
    }
}

/// A `CommandConfigurator` takes care of creating and spawning a [`Command`] for the [`CommandExecutor`].
/// # Example
/// ```
/// use std::{
///     io::Write,
///     process::{Child, Command, Stdio},
///     time::Duration,
/// };
///
/// use libafl::{
///     Error,
///     corpus::Corpus,
///     executors::{Executor, command::CommandConfigurator},
///     inputs::{BytesInput, HasTargetBytes, Input},
///     state::HasExecutions,
/// };
/// use libafl_bolts::AsSlice;
/// #[derive(Debug)]
/// struct MyExecutor;
///
/// impl CommandConfigurator<BytesInput> for MyExecutor {
///     fn spawn_child(&mut self, input: &BytesInput) -> Result<Child, Error> {
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
///
///     fn exec_timeout(&self) -> Duration {
///         Duration::from_secs(5)
///     }
///     fn exec_timeout_mut(&mut self) -> &mut Duration {
///         todo!()
///     }
/// }
///
/// fn make_executor<EM, S, Z>() -> impl Executor<EM, BytesInput, S, Z>
/// where
///     S: HasExecutions,
/// {
///     MyExecutor.into_executor((), None, None)
/// }
/// ```
pub trait CommandConfigurator<I, C = Child>: Sized {
    /// Get the stdout
    fn stdout_observer(&self) -> Option<Handle<StdOutObserver>> {
        None
    }
    /// Get the stderr
    fn stderr_observer(&self) -> Option<Handle<StdErrObserver>> {
        None
    }

    /// Spawns a new process with the given configuration.
    fn spawn_child(&mut self, input: &I) -> Result<C, Error>;

    /// Provides timeout duration for execution of the child process.
    fn exec_timeout(&self) -> Duration;
    /// Set the timeout duration for execution of the child process.
    fn exec_timeout_mut(&mut self) -> &mut Duration;

    /// Maps the exit status of the child process to an `ExitKind`.
    #[inline]
    fn exit_kind_from_status(&self, status: &std::process::ExitStatus) -> ExitKind {
        use crate::std::os::unix::process::ExitStatusExt;
        match status.signal() {
            // for reference: https://www.man7.org/linux/man-pages/man7/signal.7.html
            Some(9) => ExitKind::Oom,
            Some(_) => ExitKind::Crash,
            None => ExitKind::Ok,
        }
    }

    /// Create an `Executor` from this `CommandConfigurator`.
    fn into_executor<OT, S>(
        self,
        observers: OT,
        stdout_observer: Option<Handle<StdOutObserver>>,
        stderr_observer: Option<Handle<StdErrObserver>>,
    ) -> CommandExecutor<I, OT, S, Self, (), C> {
        CommandExecutor {
            configurer: self,
            observers,
            hooks: (),
            stderr_observer,
            stdout_observer,
            phantom: PhantomData,
        }
    }

    /// Create an `Executor` with hooks from this `CommandConfigurator`.
    fn into_executor_with_hooks<OT, S, HT>(
        self,
        observers: OT,
        hooks: HT,
        stdout_observer: Option<Handle<StdOutObserver>>,
        stderr_observer: Option<Handle<StdErrObserver>>,
    ) -> CommandExecutor<I, OT, S, Self, HT, C> {
        CommandExecutor {
            configurer: self,
            observers,
            hooks,
            stderr_observer,
            stdout_observer,
            phantom: PhantomData,
        }
    }
}

/// waitpid wrapper that ignores some signals sent by the ptraced child
#[cfg(target_os = "linux")]
fn waitpid_filtered(pid: Pid, options: Option<WaitPidFlag>) -> Result<WaitStatus, Errno> {
    loop {
        let wait_status = waitpid(pid, options);
        let sig = match &wait_status {
            // IGNORED
            Ok(Stopped(c, Signal::SIGWINCH)) if *c == pid => Signal::SIGWINCH,
            // RETURNED
            Ok(ws) => break Ok(*ws),
            Err(e) => break Err(*e),
        };
        ptrace::cont(pid, sig)?;
    }
}

#[cfg(test)]
mod tests {
    use libafl_bolts::{StdTargetArgs, tuples::Handled};
    use tuple_list::tuple_list;

    use crate::{
        events::SimpleEventManager,
        executors::{
            Executor, StdChildArgs,
            command::{CommandExecutor, InputLocation},
        },
        fuzzer::NopFuzzer,
        inputs::{BytesInput, NopInput},
        monitors::SimpleMonitor,
        observers::StdOutObserver,
        state::NopState,
    };

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_builder() {
        let mut mgr: SimpleEventManager<NopInput, _, NopState<NopInput>> =
            SimpleEventManager::new(SimpleMonitor::new(|status| {
                log::info!("{status}");
            }));

        let executor = CommandExecutor::builder()
            .program("ls")
            .input(InputLocation::Arg { argnum: 0 });
        let executor = executor.build(());
        let mut executor = executor.unwrap();

        executor
            .run_target(
                &mut NopFuzzer::new(),
                &mut NopState::<NopInput>::new(),
                &mut mgr,
                &BytesInput::new(b"test".to_vec()),
            )
            .unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_capture() {
        let mut mgr: SimpleEventManager<NopInput, _, NopState<NopInput>> =
            SimpleEventManager::new(SimpleMonitor::new(|status| {
                log::info!("{status}");
            }));

        let stdout = StdOutObserver::new("stdout".into()).unwrap();
        let handle = stdout.handle();
        let executor = CommandExecutor::builder()
            .program("ls")
            .stdout_observer(handle.clone())
            .input(InputLocation::Arg { argnum: 0 });
        let executor = executor.build(tuple_list!(stdout));
        let mut executor = executor.unwrap();

        executor
            .run_target(
                &mut NopFuzzer::new(),
                &mut NopState::<NopInput>::new(),
                &mut mgr,
                &BytesInput::new(b".".to_vec()),
            )
            .unwrap();

        assert!(executor.observers.0.output.is_some());
    }
}
