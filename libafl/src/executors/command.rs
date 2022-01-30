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
        AsSlice,
    },
    inputs::HasTargetBytes,
};
#[cfg(feature = "std")]
use crate::{executors::HasObservers, inputs::Input, observers::ObserversTuple, Error};

#[cfg(all(feature = "std", unix))]
use crate::executors::{Executor, ExitKind};

#[cfg(all(feature = "std", unix))]
use std::time::Duration;

/// How to deliver input to an external program
/// `StdIn`: The traget reads from stdin
/// `File`: The target reads from the specified [`OutFile`]
#[derive(Debug)]
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

/// A simple Configurator that takes the most common parameters
/// Writes the input either to stdio or to a file
#[derive(Debug)]
pub struct DefaultConfiguator {
    /// If set to true, the child output will remain visible
    /// By default, the child output is hidden to increase execution speed
    pub debug_child: bool,
    /// true: input gets delivered via stdink
    pub input_location: InputLocation,
    /// The Command to execute
    pub command: Command,
}

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

impl CommandConfigurator for DefaultConfiguator {
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
pub struct CommandExecutor<EM, I, OT, S, T, Z>
where
    OT: Debug,
    T: Debug,
{
    inner: T,
    /// [`crate::observers::Observer`]s for this executor
    observers: OT,
    phantom: PhantomData<(EM, I, S, Z)>,
}

impl<EM, I, OT, S, T, Z> Debug for CommandExecutor<EM, I, OT, S, T, Z>
where
    OT: Debug,
    T: Debug,
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
    OT: Debug,
    T: Debug,
{
    /// Accesses the inner value
    pub fn inner(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<EM, I, OT, S, Z> CommandExecutor<EM, I, OT, S, DefaultConfiguator, Z>
where
    OT: Debug + ObserversTuple<I, S>,
{
    /// Creates a new `CommandExecutor`.
    /// Instead of parsing the Command for `@@`, it will
    pub fn from_cmd_with_file<P>(
        cmd: &Command,
        observers: OT,
        debug_child: bool,
        path: P,
    ) -> Result<CommandExecutor<EM, I, OT, S, DefaultConfiguator, Z>, Error>
    where
        P: AsRef<Path>,
    {
        let mut command = clone_command(cmd);
        if !debug_child {
            command.stdout(Stdio::null());
            command.stderr(Stdio::null());
        }
        command.stdin(Stdio::null());
        Ok(Self {
            inner: DefaultConfiguator {
                input_location: InputLocation::File {
                    out_file: OutFile::create(path)?,
                },
                command,
                debug_child,
            },
            observers,
            phantom: PhantomData,
        })
    }

    /// Parses an AFL-like comandline, replacing `@@` with the input file.
    /// If no `@@` was found, will use stdin for input.
    pub fn parse_afl_cmdline(
        args: &[String],
        debug_child: bool,
    ) -> Result<CommandExecutor<EM, I, OT, S, DefaultConfiguator, Z>, Error> {
        let mut atat_at = None;
        let mut builder = Self::builder();
        builder.debug_child(debug_child);

        for (pos, arg) in args.iter().enumerate() {
            if arg == "@@" {
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

        builder.build()
    }

    fn builder() -> CommandExecutorBuilder<I, OT, S> {
        CommandExecutorBuilder {
            program: None,
            args_before: vec![],
            input_location: None,
            args_after: vec![],
            cwd: None,
            envs: vec![],
            debug_child: false,
            observers: None,
            phantom: PhantomData,
        }
    }
}

// this only works on unix because of the reliance on checking the process signal for detecting OOM
#[cfg(all(feature = "std", unix))]
impl<EM, I, OT: Debug, S, T: Debug, Z> Executor<EM, I, S, Z> for CommandExecutor<EM, I, OT, S, T, Z>
where
    I: Input + HasTargetBytes,
    T: CommandConfigurator,
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

        let mut child = self.inner.spawn_child(input)?;

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
impl<EM, I, OT: Debug, S, T: Debug, Z> HasObservers<I, OT, S>
    for CommandExecutor<EM, I, OT, S, T, Z>
where
    I: Input,
    OT: ObserversTuple<I, S>,
    T: CommandConfigurator,
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

/// The builder for a default [`ComandsExecutor`] that should fit most use-cases.
#[derive(Debug)]
pub struct CommandExecutorBuilder<I, OT: ObserversTuple<I, S>, S> {
    debug_child: bool,
    program: Option<OsString>,
    args_before: Vec<OsString>,
    input_location: Option<InputLocation>,
    args_after: Vec<OsString>,
    cwd: Option<PathBuf>,
    envs: Vec<(OsString, OsString)>,
    observers: Option<OT>,
    phantom: PhantomData<(I, S)>,
}

impl<I, OT: ObserversTuple<I, S>, S> CommandExecutorBuilder<I, OT, S> {
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
    pub fn arg<O: AsRef<OsStr>>(&mut self, arg: O) -> &mut CommandExecutorBuilder<I, OT, S> {
        match self.input_location {
            Some(InputLocation::StdIn) => self.args_before.push(arg.as_ref().to_owned()),
            Some(_) | None => self.args_after.push(arg.as_ref().to_owned()),
        };
        self
    }

    /// Adds a range of arguments to the program's commandline.
    pub fn args<IT, O>(&mut self, args: IT) -> &mut CommandExecutorBuilder<I, OT, S>
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
    pub fn envs<IT, K, V>(&mut self, vars: IT) -> &mut CommandExecutorBuilder<I, OT, S>
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
    pub fn env<K, V>(&mut self, key: K, val: V) -> &mut CommandExecutorBuilder<I, OT, S>
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.envs
            .push((key.as_ref().to_owned(), val.as_ref().to_owned()));
        self
    }

    /// Sets the working directory for the child process.
    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut CommandExecutorBuilder<I, OT, S> {
        self.cwd = Some(dir.as_ref().to_owned());
        self
    }

    /// If set to true, the child's output won't be redirecited to `/dev/null`.
    /// Defaults to `false`.
    pub fn debug_child(&mut self, debug_child: bool) -> &mut CommandExecutorBuilder<I, OT, S> {
        self.debug_child = debug_child;
        self
    }

    /// Sets the observers for the executor.
    /// This option is required.
    pub fn observers(&mut self, observers: OT) -> &mut CommandExecutorBuilder<I, OT, S> {
        self.observers = Some(observers);
        self
    }

    /// Builds the `ComandExecutor`
    pub fn build<EM, Z>(
        self,
    ) -> Result<CommandExecutor<EM, I, OT, S, DefaultConfiguator, Z>, Error> {
        let program = if let Some(program) = self.program {
            program
        } else {
            return Err(Error::IllegalArgument(
                "ComandExecutor::builder: no program set!".into(),
            ));
        };
        let mut command = Command::new(program);
        command.args(self.args_before);
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
        command.args(self.args_after);
        command.envs(self.envs);
        if let Some(cwd) = self.cwd {
            command.current_dir(cwd);
        }
        if !self.debug_child {
            command.stdout(Stdio::null());
            command.stderr(Stdio::null());
        }

        let configurator = DefaultConfiguator {
            debug_child: self.debug_child,
            input_location: self.input_location.unwrap(),
            command,
        };
        Ok(
            configurator.into_executor(if let Some(observer) = self.observers {
                observer
            } else {
                return Err(Error::IllegalArgument(
                    "ComandExecutor::builder: no observer set!".into(),
                ));
            }),
        )
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
pub trait CommandConfigurator: Sized + Debug {
    /// Spawns a new process with the given configuration.
    fn spawn_child<I>(&mut self, input: &I) -> Result<Child, Error>
    where
        I: Input + HasTargetBytes;

    /// Create an `Executor` from this `CommandConfigurator`.
    fn into_executor<EM, I, OT: Debug, S, Z>(
        self,
        observers: OT,
    ) -> CommandExecutor<EM, I, OT, S, Self, Z>
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
