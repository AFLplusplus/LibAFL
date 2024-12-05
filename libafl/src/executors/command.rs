//! The command executor executes a sub program for each run
use alloc::vec::Vec;
use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    ops::IndexMut,
};
#[cfg(target_os = "linux")]
use std::{
    ffi::{CStr, CString},
    os::fd::AsRawFd,
};
use std::{
    ffi::{OsStr, OsString},
    io::{Read, Write},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

#[cfg(target_os = "linux")]
use libafl_bolts::core_affinity::CoreId;
use libafl_bolts::{
    fs::{get_unique_std_input_file, InputFile},
    tuples::{Handle, MatchName, RefIndexable},
    AsSlice,
};
#[cfg(target_os = "linux")]
use libc::STDIN_FILENO;
#[cfg(target_os = "linux")]
use nix::{
    errno::Errno,
    sys::{
        ptrace,
        signal::Signal,
        wait::WaitStatus,
        wait::{
            waitpid, WaitPidFlag,
            WaitStatus::{Exited, PtraceEvent, Signaled, Stopped},
        },
    },
    unistd::Pid,
};
#[cfg(target_os = "linux")]
use typed_builder::TypedBuilder;

use super::HasTimeout;
use crate::{
    corpus::Corpus,
    executors::{hooks::ExecutorHooksTuple, Executor, ExitKind, HasObservers},
    inputs::{HasTargetBytes, Input, UsesInput},
    observers::{ObserversTuple, StdErrObserver, StdOutObserver},
    state::{HasCorpus, HasExecutions, State, UsesState},
    std::borrow::ToOwned,
    Error,
};

/// How to deliver input to an external program
/// `StdIn`: The target reads from stdin
/// `File`: The target reads from the specified [`InputFile`]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum InputLocation {
    /// Mutate a commandline argument to deliver an input
    Arg {
        /// The offset of the argument to mutate
        argnum: usize,
    },
    /// Deliver input via `StdIn`
    #[default]
    StdIn,
    /// Deliver the input via the specified [`InputFile`]
    /// You can use specify [`InputFile::create(INPUTFILE_STD)`] to use a default filename.
    File {
        /// The file to write input to. The target should read input from this location.
        out_file: InputFile,
    },
}

/// A simple Configurator that takes the most common parameters
/// Writes the input either to stdio or to a file
/// Use [`CommandExecutor::builder()`] to use this configurator.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug)]
pub struct StdCommandConfigurator {
    /// If set to true, the child output will remain visible
    /// By default, the child output is hidden to increase execution speed
    debug_child: bool,
    stdout_observer: Option<Handle<StdOutObserver>>,
    stderr_observer: Option<Handle<StdErrObserver>>,
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
    fn stdout_observer(&self) -> Option<Handle<StdOutObserver>> {
        self.stdout_observer.clone()
    }

    fn stderr_observer(&self) -> Option<Handle<StdErrObserver>> {
        self.stderr_observer.clone()
    }

    fn spawn_child(&mut self, input: &I) -> Result<Child, Error> {
        match &mut self.input_location {
            InputLocation::Arg { argnum } => {
                let args = self.command.get_args();
                let mut cmd = Command::new(self.command.get_program());

                if !self.debug_child {
                    cmd.stdout(Stdio::null());
                    cmd.stderr(Stdio::null());
                }

                if self.stdout_observer.is_some() {
                    cmd.stdout(Stdio::piped());
                }
                if self.stderr_observer.is_some() {
                    cmd.stderr(Stdio::piped());
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
            InputLocation::StdIn => {
                let mut handle = self.command.stdin(Stdio::piped()).spawn()?;
                let mut stdin = handle.stdin.take().unwrap();
                if let Err(err) = stdin.write_all(input.target_bytes().as_slice()) {
                    if err.kind() != std::io::ErrorKind::BrokenPipe {
                        return Err(err.into());
                    }
                } else if let Err(err) = stdin.flush() {
                    if err.kind() != std::io::ErrorKind::BrokenPipe {
                        return Err(err.into());
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
#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
impl<I> CommandConfigurator<I, Pid> for PTraceCommandConfigurator
where
    I: HasTargetBytes,
{
    fn spawn_child(&mut self, input: &I) -> Result<Pid, Error> {
        use nix::{
            sys::{
                personality, ptrace,
                signal::{raise, Signal},
            },
            unistd::{alarm, dup2, execve, fork, pipe, write, ForkResult},
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
                    InputLocation::StdIn => {
                        let (pipe_read, pipe_write) = pipe().unwrap();
                        write(pipe_write, &input.target_bytes()).unwrap();
                        dup2(pipe_read.as_raw_fd(), STDIN_FILENO).unwrap();
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
pub struct CommandExecutor<OT, S, T, HT = (), C = Child> {
    /// The wrapped command configurer
    configurer: T,
    /// The observers used by this executor
    observers: OT,
    hooks: HT,
    phantom: PhantomData<S>,
    phantom_child: PhantomData<C>,
}

impl CommandExecutor<(), (), ()> {
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

impl<OT, S, T, HT, C> Debug for CommandExecutor<OT, S, T, HT, C>
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
            .finish()
    }
}

impl<OT, S, T, HT, C> CommandExecutor<OT, S, T, HT, C>
where
    T: Debug,
    OT: Debug,
{
    /// Accesses the inner value
    pub fn inner(&mut self) -> &mut T {
        &mut self.configurer
    }
}

// this only works on unix because of the reliance on checking the process signal for detecting OOM
impl<I, OT, S, T> CommandExecutor<OT, S, T>
where
    S: State + HasExecutions + UsesInput<Input = I>,
    T: CommandConfigurator<I> + Debug,
    OT: Debug + ObserversTuple<I, S>,
{
    fn execute_input_with_command(&mut self, state: &mut S, input: &I) -> Result<ExitKind, Error> {
        use wait_timeout::ChildExt;

        *state.executions_mut() += 1;
        self.observers.pre_exec_child_all(state, input)?;

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

        self.observers
            .post_exec_child_all(state, input, &exit_kind)?;

        if let Some(h) = &mut self.configurer.stdout_observer() {
            let mut stdout = Vec::new();
            child.stdout.as_mut().ok_or_else(|| {
                 Error::illegal_state(
                     "Observer tries to read stderr, but stderr was not `Stdio::pipe` in CommandExecutor",
                 )
             })?.read_to_end(&mut stdout)?;
            let mut observers = self.observers_mut();
            let obs = observers.index_mut(h);
            obs.observe_stdout(&stdout);
        }
        if let Some(h) = &mut self.configurer.stderr_observer() {
            let mut stderr = Vec::new();
            child.stderr.as_mut().ok_or_else(|| {
                 Error::illegal_state(
                     "Observer tries to read stderr, but stderr was not `Stdio::pipe` in CommandExecutor",
                 )
             })?.read_to_end(&mut stderr)?;
            let mut observers = self.observers_mut();
            let obs = observers.index_mut(h);
            obs.observe_stderr(&stderr);
        }
        Ok(exit_kind)
    }
}

impl<EM, OT, S, T, Z> Executor<EM, Z> for CommandExecutor<OT, S, T>
where
    EM: UsesState<State = S>,
    S: State + HasExecutions + UsesInput,
    T: CommandConfigurator<S::Input> + Debug,
    OT: Debug + MatchName + ObserversTuple<S::Input, S>,
    Z: UsesState<State = S>,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut Self::State,
        _mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        self.execute_input_with_command(state, input)
    }
}

// this only works on unix because of the reliance on checking the process signal for detecting OOM
impl<OT, S, T> HasTimeout for CommandExecutor<OT, S, T>
where
    S: HasCorpus,
    T: CommandConfigurator<<S::Corpus as Corpus>::Input>,
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
impl<EM, OT, S, T, Z, HT> Executor<EM, Z> for CommandExecutor<OT, S, T, HT, Pid>
where
    EM: UsesState<State = S>,
    S: State + HasExecutions + UsesInput,
    T: CommandConfigurator<S::Input, Pid> + Debug,
    OT: Debug + MatchName + ObserversTuple<S::Input, S>,
    Z: UsesState<State = S>,
    HT: ExecutorHooksTuple<S>,
{
    /// Linux specific low level implementation, to directly handle `fork`, `exec` and use linux
    /// `ptrace`
    ///
    /// Hooks' `pre_exec` and observers' `pre_exec_child` are called with the child process stopped
    /// just before the `exec` return (after forking).
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut Self::State,
        _mgr: &mut EM,
        input: &Self::Input,
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
            self.hooks.init_all::<Self>(state);
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
                return Err(Error::unsupported(
                    format!("Target program returned an unexpected state when waiting on it. {s:?} (waiting for pid {child})")
                ));
            }
        };

        self.hooks.post_exec_all(state, input);
        self.observers.post_exec_child_all(state, input, &res)?;
        Ok(res)
    }
}

impl<OT, S, T, HT, C> UsesState for CommandExecutor<OT, S, T, HT, C>
where
    S: State,
{
    type State = S;
}

impl<OT, S, T, HT, C> HasObservers for CommandExecutor<OT, S, T, HT, C>
where
    S: State,
    T: Debug,
    OT: ObserversTuple<S::Input, S>,
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
    stdout: Option<Handle<StdOutObserver>>,
    stderr: Option<Handle<StdErrObserver>>,
    debug_child: bool,
    program: Option<OsString>,
    args: Vec<OsString>,
    input_location: InputLocation,
    cwd: Option<PathBuf>,
    envs: Vec<(OsString, OsString)>,
    timeout: Duration,
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
            stdout: None,
            stderr: None,
            program: None,
            args: vec![],
            input_location: InputLocation::StdIn,
            cwd: None,
            envs: vec![],
            timeout: Duration::from_secs(5),
            debug_child: false,
        }
    }

    /// Set the binary to execute
    /// This option is required.
    pub fn program<O>(&mut self, program: O) -> &mut Self
    where
        O: AsRef<OsStr>,
    {
        self.program = Some(program.as_ref().to_owned());
        self
    }

    /// Set the input mode and location.
    /// This option is mandatory, if not set, the `build` method will error.
    fn input(&mut self, input: InputLocation) -> &mut Self {
        // This is a fatal error in the user code, no point in returning Err.
        assert_eq!(
            self.input_location,
            InputLocation::StdIn,
            "input location already set to non-stdin, cannot set it again"
        );
        self.input_location = input;
        self
    }

    /// Sets the input mode to [`InputLocation::Arg`] and uses the current arg offset as `argnum`.
    /// During execution, at input will be provided _as argument_ at this position.
    /// Use [`Self::arg_input_file_std`] if you want to provide the input as a file instead.
    pub fn arg_input_arg(&mut self) -> &mut Self {
        let argnum = self.args.len();
        self.input(InputLocation::Arg { argnum });
        // Placeholder arg that gets replaced with the input name later.
        self.arg("PLACEHOLDER");
        self
    }

    /// Sets the stdout observer
    pub fn stdout_observer(&mut self, stdout: Handle<StdOutObserver>) -> &mut Self {
        self.stdout = Some(stdout);
        self
    }

    /// Sets the stderr observer
    pub fn stderr_observer(&mut self, stderr: Handle<StdErrObserver>) -> &mut Self {
        self.stderr = Some(stderr);
        self
    }

    /// Sets the input mode to [`InputLocation::File`]
    /// and adds the filename as arg to at the current position.
    /// Uses a default filename.
    /// Use [`Self::arg_input_file`] to specify a custom filename.
    pub fn arg_input_file_std(&mut self) -> &mut Self {
        self.arg_input_file(get_unique_std_input_file());
        self
    }

    /// Sets the input mode to [`InputLocation::File`]
    /// and adds the filename as arg to at the current position.
    pub fn arg_input_file<P: AsRef<Path>>(&mut self, path: P) -> &mut Self {
        self.arg(path.as_ref());
        let out_file_std = InputFile::create(path.as_ref()).unwrap();
        self.input(InputLocation::File {
            out_file: out_file_std,
        });
        self
    }

    /// Adds an argument to the program's commandline.
    pub fn arg<O: AsRef<OsStr>>(&mut self, arg: O) -> &mut CommandExecutorBuilder {
        self.args.push(arg.as_ref().to_owned());
        self
    }

    /// Adds a range of arguments to the program's commandline.
    pub fn args<IT, O>(&mut self, args: IT) -> &mut CommandExecutorBuilder
    where
        IT: IntoIterator<Item = O>,
        O: AsRef<OsStr>,
    {
        for arg in args {
            self.arg(arg.as_ref());
        }
        self
    }

    /// Adds a range of environment variables to the executed command.
    pub fn envs<IT, K, V>(&mut self, vars: IT) -> &mut CommandExecutorBuilder
    where
        IT: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        for (ref key, ref val) in vars {
            self.env(key.as_ref(), val.as_ref());
        }
        self
    }

    /// Adds an environment variable to the executed command.
    pub fn env<K, V>(&mut self, key: K, val: V) -> &mut CommandExecutorBuilder
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.envs
            .push((key.as_ref().to_owned(), val.as_ref().to_owned()));
        self
    }

    /// Sets the working directory for the child process.
    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut CommandExecutorBuilder {
        self.cwd = Some(dir.as_ref().to_owned());
        self
    }

    /// If set to true, the child's output won't be redirecited to `/dev/null`.
    /// Defaults to `false`.
    pub fn debug_child(&mut self, debug_child: bool) -> &mut CommandExecutorBuilder {
        self.debug_child = debug_child;
        self
    }

    /// Sets the execution timeout duration.
    pub fn timeout(&mut self, timeout: Duration) -> &mut CommandExecutorBuilder {
        self.timeout = timeout;
        self
    }

    /// Builds the `CommandExecutor`
    pub fn build<OT, S>(
        &self,
        observers: OT,
    ) -> Result<CommandExecutor<OT, S, StdCommandConfigurator>, Error>
    where
        OT: MatchName + ObserversTuple<S::Input, S>,
        S: UsesInput,
        S::Input: Input + HasTargetBytes,
    {
        let Some(program) = &self.program else {
            return Err(Error::illegal_argument(
                "CommandExecutor::builder: no program set!",
            ));
        };

        let mut command = Command::new(program);
        match &self.input_location {
            InputLocation::StdIn => {
                command.stdin(Stdio::piped());
            }
            InputLocation::File { .. } | InputLocation::Arg { .. } => {
                command.stdin(Stdio::null());
            }
        }
        command.args(&self.args);
        command.envs(
            self.envs
                .iter()
                .map(|(k, v)| (k.as_os_str(), v.as_os_str())),
        );
        if let Some(cwd) = &self.cwd {
            command.current_dir(cwd);
        }
        if !self.debug_child {
            command.stdout(Stdio::null());
            command.stderr(Stdio::null());
        }

        if self.stdout.is_some() {
            command.stdout(Stdio::piped());
        }

        if self.stderr.is_some() {
            command.stderr(Stdio::piped());
        }

        let configurator = StdCommandConfigurator {
            debug_child: self.debug_child,
            stdout_observer: self.stdout.clone(),
            stderr_observer: self.stderr.clone(),
            input_location: self.input_location.clone(),
            timeout: self.timeout,
            command,
        };
        Ok(
            <StdCommandConfigurator as CommandConfigurator<S::Input>>::into_executor::<OT, S>(
                configurator,
                observers,
            ),
        )
    }
}

/// A `CommandConfigurator` takes care of creating and spawning a [`Command`] for the [`CommandExecutor`].
/// # Example
/// ```
/// use std::{io::Write, process::{Stdio, Command, Child}, time::Duration};
/// use libafl::{Error, inputs::{BytesInput, HasTargetBytes, Input, UsesInput}, executors::{Executor, command::CommandConfigurator}, state::{UsesState, HasExecutions}};
/// use libafl_bolts::AsSlice;
/// #[derive(Debug)]
/// struct MyExecutor;
///
/// impl CommandConfigurator<BytesInput> for MyExecutor {
///     fn spawn_child(
///        &mut self,
///        input: &BytesInput,
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
///
///     fn exec_timeout(&self) -> Duration {
///         Duration::from_secs(5)
///     }
///     fn exec_timeout_mut(&mut self) -> &mut Duration {
///         todo!()
///     }
/// }
///
/// fn make_executor<EM, Z>() -> impl Executor<EM, Z>
/// where
///     EM: UsesState,
///     Z: UsesState<State = EM::State>,
///     EM::State: UsesInput<Input = BytesInput> + HasExecutions,
/// {
///     MyExecutor.into_executor(())
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
    fn into_executor<OT, S>(self, observers: OT) -> CommandExecutor<OT, S, Self, (), C>
    where
        OT: MatchName,
    {
        CommandExecutor {
            configurer: self,
            observers,
            hooks: (),
            phantom: PhantomData,
            phantom_child: PhantomData,
        }
    }

    /// Create an `Executor` with hooks from this `CommandConfigurator`.
    fn into_executor_with_hooks<OT, S, HT>(
        self,
        observers: OT,
        hooks: HT,
    ) -> CommandExecutor<OT, S, Self, HT, C>
    where
        OT: MatchName,
        HT: ExecutorHooksTuple<S>,
        S: UsesInput<Input = I>,
    {
        CommandExecutor {
            configurer: self,
            observers,
            hooks,
            phantom: PhantomData,
            phantom_child: PhantomData,
        }
    }
}

/// waitpid wrapper that ignores some signals sent by the ptraced child
#[cfg(all(feature = "std", target_os = "linux"))]
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
    use crate::{
        events::SimpleEventManager,
        executors::{
            command::{CommandExecutor, InputLocation},
            Executor,
        },
        fuzzer::NopFuzzer,
        inputs::BytesInput,
        monitors::SimpleMonitor,
        state::NopState,
    };

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_builder() {
        let mut mgr = SimpleEventManager::new(SimpleMonitor::new(|status| {
            log::info!("{status}");
        }));

        let mut executor = CommandExecutor::builder();
        executor
            .program("ls")
            .input(InputLocation::Arg { argnum: 0 });
        let executor = executor.build(());
        let mut executor = executor.unwrap();

        executor
            .run_target(
                &mut NopFuzzer::new(),
                &mut NopState::new(),
                &mut mgr,
                &BytesInput::new(b"test".to_vec()),
            )
            .unwrap();
    }
}
