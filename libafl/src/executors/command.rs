//! The command executor executes a sub program for each run
use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

#[cfg(feature = "std")]
use std::process::Child;
use std::{
    ffi::{OsStr, OsString},
    io::Write,
    os::unix::prelude::OsStringExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::{
    bolts::{
        fs::{OutFile, DEFAULT_OUTFILE},
        tuples::MatchFirstType,
        AsSlice,
    },
    inputs::HasTargetBytes,
    observers::{ASANBacktraceObserver, ObserversTuple},
};
#[cfg(feature = "std")]
use crate::{inputs::Input, Error};

#[cfg(all(feature = "std", unix))]
use crate::executors::{Executor, ExitKind};

#[cfg(all(feature = "std", unix))]
use std::time::Duration;

use super::HasObservers;

/// How to deliver input to an external program
/// `StdIn`: The traget reads from stdin
/// `File`: The target reads from the specified [`OutFile`]
#[derive(Debug, Clone)]
pub enum InputLocation {
    /// Mutate a commandline argument to deliver an input
    Arg {
        /// The offset of the argument to mutate
        argnum: usize,
    },
    /// Deliver input via `StdIn`
    StdIn,
    /// Deliver the iniput via the specified [`OutFile`]
    /// You can use specify [`OutFile::create(DEFAULT_OUTFILE)`] to use a default filename.
    File {
        /// The fiel to write input to. The target should read input from this location.
        out_file: OutFile,
    },
}

/// Clones a [`Command`] (without stdio and stdout/stderr - they are not accesible)
fn clone_command(cmd: &Command) -> Command {
    let mut new_cmd = Command::new(cmd.get_program());
    new_cmd.args(cmd.get_args());
    new_cmd.env_clear();
    new_cmd.envs(
        cmd.get_envs()
            .filter_map(|(key, value)| value.map(|value| (key, value))),
    );
    if let Some(cwd) = cmd.get_current_dir() {
        new_cmd.current_dir(cwd);
    }
    new_cmd
}

/// A simple Configurator that takes the most common parameters
/// Writes the input either to stdio or to a file
#[derive(Debug)]
pub struct StdCommandConfigurator {
    /// If set to true, the child output will remain visible
    /// By default, the child output is hidden to increase execution speed
    pub debug_child: bool,
    /// true: input gets delivered via stdink
    pub input_location: InputLocation,
    /// The Command to execute
    pub command: Command,
}

impl CommandConfigurator for StdCommandConfigurator {
    fn spawn_child<I>(&mut self, input: &I) -> Result<Child, Error>
    where
        I: Input + HasTargetBytes,
    {
        match &mut self.input_location {
            InputLocation::Arg { argnum } => {
                let args = self.command.get_args();
                let mut cmd = Command::new(self.command.get_program());

                if !self.debug_child {
                    cmd.stdout(Stdio::null());
                    cmd.stderr(Stdio::null());
                }

                for (i, arg) in args.enumerate() {
                    if i == *argnum {
                        cmd.arg(OsString::from_vec(input.target_bytes().as_slice().to_vec()));
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
                self.command.stdin(Stdio::piped()).spawn()?;
                let mut handle = self.command.spawn()?;
                let mut stdin = handle.stdin.take().unwrap();
                stdin.write_all(input.target_bytes().as_slice())?;
                stdin.flush()?;
                drop(stdin);
                Ok(handle)
            }
            InputLocation::File { out_file } => {
                out_file.write_buf(input.target_bytes().as_slice())?;
                Ok(self.command.spawn()?)
            }
        }
    }
}

/// A `CommandExecutor` is a wrapper around [`std::process::Command`] to execute a target as a child process.
/// Construct a `CommandExecutor` by implementing [`CommandConfigurator`] for a type of your choice and calling [`CommandConfigurator::into_executor`] on it.
/// Instead, you can use [`CommandExecutor::builder()`] to construct a [`CommandExecutor`] backed by a [`StdCommandConfigurator`].
pub struct CommandExecutor<EM, I, OT, S, T, Z>
where
    T: Debug,
    OT: Debug,
{
    inner: T,
    observers: OT,
    /// cache if the AsanBacktraceObserver is present
    has_asan_observer: bool,
    phantom: PhantomData<(EM, I, S, Z)>,
}

impl CommandExecutor<(), (), (), (), (), ()> {
    /// Creates a builder for a new [`CommandExecutor`],
    /// backed by a [`StdCommandConfigurator`]
    /// This is usually the easiest way to construct a [`CommandExecutor`].
    #[must_use]
    pub fn builder() -> CommandExecutorBuilder {
        CommandExecutorBuilder::new()
    }
}

impl<EM, I, OT, S, T, Z> Debug for CommandExecutor<EM, I, OT, S, T, Z>
where
    T: Debug,
    OT: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandExecutor")
            .field("inner", &self.inner)
            .field("observers", &self.observers)
            .finish()
    }
}

impl<EM, I, OT, S, T, Z> CommandExecutor<EM, I, OT, S, T, Z>
where
    T: Debug,
    OT: Debug,
{
    /// Accesses the inner value
    pub fn inner(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<EM, I, OT, S, Z> CommandExecutor<EM, I, OT, S, StdCommandConfigurator, Z>
where
    OT: MatchFirstType + Debug,
{
    /// Creates a new `CommandExecutor`.
    /// Instead of parsing the Command for `@@`, it will
    pub fn from_cmd_with_file<P>(
        cmd: &Command,
        debug_child: bool,
        observers: OT,
        path: P,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mut command = clone_command(cmd);
        if !debug_child {
            command.stdout(Stdio::null());
            command.stderr(Stdio::null());
        }
        if observers
            .match_first_type::<ASANBacktraceObserver>()
            .is_some()
        {
            // we need stderr
            command.stderr(Stdio::piped());
        }
        command.stdin(Stdio::null());

        let has_asan_observer = observers
            .match_first_type::<ASANBacktraceObserver>()
            .is_some();

        Ok(Self {
            observers,
            has_asan_observer,
            inner: StdCommandConfigurator {
                input_location: InputLocation::File {
                    out_file: OutFile::create(path)?,
                },
                command,
                debug_child,
            },
            phantom: PhantomData,
        })
    }

    /// Parses an AFL-like comandline, replacing `@@` with the input file.
    /// If no `@@` was found, will use stdin for input.
    /// The arg 0 is the program.
    pub fn parse_afl_cmdline<IT, O>(
        args: IT,
        observers: OT,
        debug_child: bool,
    ) -> Result<Self, Error>
    where
        IT: IntoIterator<Item = O>,
        O: AsRef<OsStr>,
    {
        let mut atat_at = None;
        let mut builder = CommandExecutorBuilder::new();
        builder.debug_child(debug_child);
        let afl_delim = OsStr::new("@@");

        for (pos, arg) in args.into_iter().enumerate() {
            if pos == 0 {
                if arg.as_ref() == afl_delim {
                    return Err(Error::IllegalArgument(
                        "The first argument must not be @@ but the program to execute".into(),
                    ));
                }
                builder.program(arg);
            } else if arg.as_ref() == afl_delim {
                if atat_at.is_some() {
                    return Err(Error::IllegalArgument(
                        "Multiple @@ in afl commandline are not permitted".into(),
                    ));
                }
                atat_at = Some(pos);
                builder.input(InputLocation::File {
                    out_file: OutFile::create(DEFAULT_OUTFILE)?,
                });
                builder.arg(DEFAULT_OUTFILE);
            } else {
                builder.arg(arg);
            }
        }

        if atat_at.is_none() {
            builder.input(InputLocation::StdIn);
        }

        builder.build(observers)
    }
}

// this only works on unix because of the reliance on checking the process signal for detecting OOM
#[cfg(all(feature = "std", unix))]
impl<EM, I, OT, S, T, Z> Executor<EM, I, S, Z> for CommandExecutor<EM, I, OT, S, T, Z>
where
    I: Input + HasTargetBytes,
    T: CommandConfigurator,
    OT: Debug + MatchFirstType,
    T: Debug,
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

        let mut child = self.inner.spawn_child(input)?;

        let res = match child
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
        };

        if self.has_asan_observer {
            let stderr = child.stderr.as_mut().ok_or_else(|| {
                Error::IllegalState(
                    "Using ASANBacktraceObserver but stderr was not `Stdio::pipe` in CommandExecutor".into(),
                )
            })?;
            let obs = self
                .observers
                .match_first_type_mut::<ASANBacktraceObserver>()
                .unwrap();
            obs.parse_asan_output_from_childstderr(stderr);
        };

        res
    }
}

impl<EM, I, OT: ObserversTuple<I, S>, S, T: Debug, Z> HasObservers<I, OT, S>
    for CommandExecutor<EM, I, OT, S, T, Z>
{
    fn observers(&self) -> &OT {
        &self.observers
    }

    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}

/// The builder for a default [`CommandExecutor`] that should fit most use-cases.
#[derive(Debug, Clone)]
pub struct CommandExecutorBuilder {
    debug_child: bool,
    program: Option<OsString>,
    args_before: Vec<OsString>,
    input_location: Option<InputLocation>,
    args_after: Vec<OsString>,
    cwd: Option<PathBuf>,
    envs: Vec<(OsString, OsString)>,
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
            program: None,
            args_before: vec![],
            input_location: None,
            args_after: vec![],
            cwd: None,
            envs: vec![],
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
    pub fn input(&mut self, input: InputLocation) -> &mut Self {
        // This is an error in the user code, no point in returning Err.
        assert!(
            self.input_location.is_none(),
            "input location already set, cannot set it again"
        );
        self.input_location = Some(input);
        self
    }

    /// Adds an argument to the program's commandline.
    pub fn arg<O: AsRef<OsStr>>(&mut self, arg: O) -> &mut CommandExecutorBuilder {
        match self.input_location {
            Some(InputLocation::StdIn) => self.args_before.push(arg.as_ref().to_owned()),
            Some(_) | None => self.args_after.push(arg.as_ref().to_owned()),
        };
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

    /// Builds the `ComandExecutor`
    pub fn build<EM, I, OT, S, Z>(
        &self,
        observers: OT,
    ) -> Result<CommandExecutor<EM, I, OT, S, StdCommandConfigurator, Z>, Error>
    where
        OT: Debug + MatchFirstType,
    {
        let program = if let Some(program) = &self.program {
            program
        } else {
            return Err(Error::IllegalArgument(
                "ComandExecutor::builder: no program set!".into(),
            ));
        };
        let mut command = Command::new(program);
        command.args(&self.args_before);
        match &self.input_location {
            Some(InputLocation::StdIn) => {
                command.stdin(Stdio::piped());
            }
            Some(InputLocation::File { out_file }) => {
                command.stdin(Stdio::null());
                command.arg(&out_file.path);
            }
            Some(InputLocation::Arg { .. }) => {
                command.stdin(Stdio::null());
                command.arg("DUMMY");
            }
            None => {
                return Err(Error::IllegalArgument(
                    "ComandExecutor::builder: no input_location set!".into(),
                ))
            }
        }
        command.args(&self.args_after);
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
        if observers
            .match_first_type::<ASANBacktraceObserver>()
            .is_some()
        {
            // we need stderr
            command.stderr(Stdio::piped());
        }

        let configurator = StdCommandConfigurator {
            debug_child: self.debug_child,
            input_location: self.input_location.clone().unwrap(),
            command,
        };
        Ok(configurator.into_executor(observers))
    }
}

/// A `CommandConfigurator` takes care of creating and spawning a [`std::process::Command`] for the [`CommandExecutor`].
/// # Example
/// ```
/// use std::{io::Write, process::{Stdio, Command, Child}};
/// use libafl::{Error, bolts::AsSlice, inputs::{Input, HasTargetBytes}, executors::{Executor, command::CommandConfigurator}};
/// #[derive(Debug)]
/// struct MyExecutor;
///
/// impl CommandConfigurator for MyExecutor {
///     fn spawn_child<I: HasTargetBytes>(
///        &mut self,
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
pub trait CommandConfigurator: Sized + Debug {
    /// Spawns a new process with the given configuration.
    fn spawn_child<I>(&mut self, input: &I) -> Result<Child, Error>
    where
        I: Input + HasTargetBytes;

    /// Create an `Executor` from this `CommandConfigurator`.
    fn into_executor<EM, I, OT, S, Z>(self, observers: OT) -> CommandExecutor<EM, I, OT, S, Self, Z>
    where
        OT: Debug + MatchFirstType,
    {
        let has_asan_observer = observers
            .match_first_type::<ASANBacktraceObserver>()
            .is_some();

        CommandExecutor {
            observers,
            has_asan_observer,
            inner: self,
            phantom: PhantomData,
        }
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
        inputs::BytesInput,
        monitors::SimpleMonitor,
    };

    #[test]
    #[cfg(unix)]
    fn test_builder() {
        let mut mgr = SimpleEventManager::<BytesInput, _>::new(SimpleMonitor::new(|status| {
            println!("{}", status);
        }));

        let mut executor = CommandExecutor::builder();
        executor
            .program("ls")
            .input(InputLocation::Arg { argnum: 0 });
        let executor = executor.build(());
        let mut executor = executor.unwrap();

        executor
            .run_target(
                &mut (),
                &mut (),
                &mut mgr,
                &BytesInput::new(b"test".to_vec()),
            )
            .unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn test_parse_afl_cmdline() {
        let mut mgr = SimpleEventManager::<BytesInput, _>::new(SimpleMonitor::new(|status| {
            println!("{}", status);
        }));

        let mut executor =
            CommandExecutor::parse_afl_cmdline(&["file".to_string(), "@@".to_string()], (), true)
                .unwrap();
        executor
            .run_target(
                &mut (),
                &mut (),
                &mut mgr,
                &BytesInput::new(b"test".to_vec()),
            )
            .unwrap();
    }
}
