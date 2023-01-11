//! The command executor executes a sub program for each run
use alloc::vec::Vec;
use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(feature = "std")]
use std::process::Child;
#[cfg(all(feature = "std", unix))]
use std::time::Duration;
use std::{
    ffi::{OsStr, OsString},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use super::HasObservers;
#[cfg(all(feature = "std", unix))]
use crate::executors::{Executor, ExitKind};
use crate::{
    bolts::{
        fs::{InputFile, INPUTFILE_STD},
        tuples::MatchName,
        AsSlice,
    },
    inputs::{HasTargetBytes, UsesInput},
    observers::{ObserversTuple, UsesObservers},
    state::UsesState,
    std::borrow::ToOwned,
};
#[cfg(feature = "std")]
use crate::{inputs::Input, Error};

/// How to deliver input to an external program
/// `StdIn`: The target reads from stdin
/// `File`: The target reads from the specified [`InputFile`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputLocation {
    /// Mutate a commandline argument to deliver an input
    Arg {
        /// The offset of the argument to mutate
        argnum: usize,
    },
    /// Deliver input via `StdIn`
    StdIn,
    /// Deliver the input via the specified [`InputFile`]
    /// You can use specify [`InputFile::create(INPUTFILE_STD)`] to use a default filename.
    File {
        /// The file to write input to. The target should read input from this location.
        out_file: InputFile,
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
/// Use [`CommandExecutor::builder()`] to use this configurator.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug)]
pub struct StdCommandConfigurator {
    /// If set to true, the child output will remain visible
    /// By default, the child output is hidden to increase execution speed
    debug_child: bool,
    has_stdout_observer: bool,
    has_stderr_observer: bool,
    /// true: input gets delivered via stdink
    input_location: InputLocation,
    /// The Command to execute
    command: Command,
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

                if self.has_stdout_observer {
                    cmd.stdout(Stdio::piped());
                }
                if self.has_stderr_observer {
                    cmd.stderr(Stdio::piped());
                }

                for (i, arg) in args.enumerate() {
                    if i == *argnum {
                        debug_assert_eq!(arg, "DUMMY");
                        #[cfg(unix)]
                        cmd.arg(OsStr::from_bytes(input.target_bytes().as_slice()));
                        // There is an issue here that the chars on windows are 16 bit wide.
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
pub struct CommandExecutor<EM, OT, S, T, Z> {
    /// The wrapped comand configurer
    configurer: T,
    /// The observers used by this executor
    observers: OT,
    phantom: PhantomData<(EM, S, Z)>,
}

impl CommandExecutor<(), (), (), (), ()> {
    /// Creates a builder for a new [`CommandExecutor`],
    /// backed by a [`StdCommandConfigurator`]
    /// This is usually the easiest way to construct a [`CommandExecutor`].
    ///
    /// It mimics the api of [`Command`], specifically, you will use
    /// `arg`, `args`, `env`, and so on.
    ///
    /// By default, input is read from stdin, unless you specify a different location using
    /// * `arg_input_arg` for input delivered _as_ an command line argument
    /// * `arg_input_file` for input via a file of a specific name
    /// * `arg_input_file_std` for a file with default name
    /// (at the right location in the arguments)
    #[must_use]
    pub fn builder() -> CommandExecutorBuilder {
        CommandExecutorBuilder::new()
    }
}

impl<EM, OT, S, T, Z> Debug for CommandExecutor<EM, OT, S, T, Z>
where
    T: Debug,
    OT: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandExecutor")
            .field("inner", &self.configurer)
            .field("observers", &self.observers)
            .finish()
    }
}

impl<EM, OT, S, T, Z> CommandExecutor<EM, OT, S, T, Z>
where
    T: Debug,
    OT: Debug,
{
    /// Accesses the inner value
    pub fn inner(&mut self) -> &mut T {
        &mut self.configurer
    }
}

impl<EM, OT, S, Z> CommandExecutor<EM, OT, S, StdCommandConfigurator, Z>
where
    OT: MatchName + Debug + ObserversTuple<S>,
    S: UsesInput,
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
        command.stdin(Stdio::null());

        let has_stdout_observer = observers.observes_stdout();
        if has_stdout_observer {
            command.stdout(Stdio::piped());
        }
        let has_stderr_observer = observers.observes_stderr();
        if has_stderr_observer {
            command.stderr(Stdio::piped());
        }

        Ok(Self {
            observers,
            configurer: StdCommandConfigurator {
                input_location: InputLocation::File {
                    out_file: InputFile::create(path)?,
                },
                command,
                debug_child,
                has_stdout_observer,
                has_stderr_observer,
            },
            phantom: PhantomData,
        })
    }

    /// Parses an AFL-like commandline, replacing `@@` with the input file.
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
                    return Err(Error::illegal_argument(
                        "The first argument must not be @@ but the program to execute",
                    ));
                }
                builder.program(arg);
            } else if arg.as_ref() == afl_delim {
                if atat_at.is_some() {
                    return Err(Error::illegal_argument(
                        "Multiple @@ in afl commandline are not permitted",
                    ));
                }
                atat_at = Some(pos);
                builder.arg_input_file_std();
            } else {
                builder.arg(arg);
            }
        }

        builder.build(observers)
    }
}

// this only works on unix because of the reliance on checking the process signal for detecting OOM
#[cfg(all(feature = "std", unix))]
impl<EM, OT, S, T, Z> Executor<EM, Z> for CommandExecutor<EM, OT, S, T, Z>
where
    EM: UsesState<State = S>,
    S: UsesInput,
    S::Input: HasTargetBytes,
    T: CommandConfigurator + Debug,
    OT: Debug + MatchName + ObserversTuple<S>,
    Z: UsesState<State = S>,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut Self::State,
        _mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        use std::os::unix::prelude::ExitStatusExt;

        use wait_timeout::ChildExt;

        let mut child = self.configurer.spawn_child(input)?;

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

        if self.observers.observes_stderr() {
            let mut stderr = Vec::new();
            child.stderr.as_mut().ok_or_else(|| {
                Error::illegal_state(
                    "Observer tries to read stderr, but stderr was not `Stdio::pipe` in CommandExecutor",
                )
            })?.read_to_end(&mut stderr)?;
            self.observers.observe_stderr(&stderr);
        }
        if self.observers.observes_stdout() {
            let mut stdout = Vec::new();
            child.stdout.as_mut().ok_or_else(|| {
                Error::illegal_state(
                    "Observer tries to read stdout, but stdout was not `Stdio::pipe` in CommandExecutor",
                )
            })?.read_to_end(&mut stdout)?;
            self.observers.observe_stdout(&stdout);
        }

        res
    }
}

impl<EM, OT, S, T, Z> UsesState for CommandExecutor<EM, OT, S, T, Z>
where
    S: UsesInput,
{
    type State = S;
}

impl<EM, OT, S, T, Z> UsesObservers for CommandExecutor<EM, OT, S, T, Z>
where
    OT: ObserversTuple<S>,
    S: UsesInput,
{
    type Observers = OT;
}

impl<EM, OT, S, T, Z> HasObservers for CommandExecutor<EM, OT, S, T, Z>
where
    S: UsesInput,
    T: Debug,
    OT: ObserversTuple<S>,
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
    args: Vec<OsString>,
    input_location: InputLocation,
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
            args: vec![],
            input_location: InputLocation::StdIn,
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
        self.arg("DUMMY");
        self
    }

    /// Sets the input mode to [`InputLocation::File`]
    /// and adds the filename as arg to at the current position.
    /// Uses a default filename.
    /// Use [`Self::arg_input_file`] to specify a custom filename.
    pub fn arg_input_file_std(&mut self) -> &mut Self {
        self.arg_input_file(INPUTFILE_STD);
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

    /// Builds the `ComandExecutor`
    pub fn build<EM, OT, S, Z>(
        &self,
        observers: OT,
    ) -> Result<CommandExecutor<EM, OT, S, StdCommandConfigurator, Z>, Error>
    where
        OT: Debug + MatchName + ObserversTuple<S>,
        S: UsesInput,
    {
        let program = if let Some(program) = &self.program {
            program
        } else {
            return Err(Error::illegal_argument(
                "ComandExecutor::builder: no program set!",
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
        if observers.observes_stdout() {
            command.stdout(Stdio::piped());
        }
        if observers.observes_stderr() {
            // we need stderr for `AsanBacktaceObserver`, and others
            command.stderr(Stdio::piped());
        }

        let configurator = StdCommandConfigurator {
            debug_child: self.debug_child,
            has_stdout_observer: observers.observes_stdout(),
            has_stderr_observer: observers.observes_stderr(),
            input_location: self.input_location.clone(),
            command,
        };
        Ok(configurator.into_executor::<EM, OT, S, Z>(observers))
    }
}

/// A `CommandConfigurator` takes care of creating and spawning a [`std::process::Command`] for the [`CommandExecutor`].
/// # Example
#[cfg_attr(all(feature = "std", unix), doc = " ```")]
#[cfg_attr(not(all(feature = "std", unix)), doc = " ```ignore")]
/// use std::{io::Write, process::{Stdio, Command, Child}};
/// use libafl::{Error, bolts::AsSlice, inputs::{HasTargetBytes, Input, UsesInput}, executors::{Executor, command::CommandConfigurator}, state::UsesState};
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
/// fn make_executor<EM, Z>() -> impl Executor<EM, Z>
/// where
///     EM: UsesState,
///     Z: UsesState<State = EM::State>,
///     EM::State: UsesInput,
///     EM::Input: HasTargetBytes
/// {
///     MyExecutor.into_executor(())
/// }
/// ```

#[cfg(all(feature = "std", any(unix, doc)))]
pub trait CommandConfigurator: Sized + Debug {
    /// Spawns a new process with the given configuration.
    fn spawn_child<I>(&mut self, input: &I) -> Result<Child, Error>
    where
        I: Input + HasTargetBytes;

    /// Create an `Executor` from this `CommandConfigurator`.
    fn into_executor<EM, OT, S, Z>(self, observers: OT) -> CommandExecutor<EM, OT, S, Self, Z>
    where
        OT: Debug + MatchName,
    {
        CommandExecutor {
            observers,
            configurer: self,
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
        state::NopState,
        NopFuzzer,
    };

    #[test]
    #[cfg(unix)]
    fn test_builder() {
        let mut mgr = SimpleEventManager::new(SimpleMonitor::new(|status| {
            println!("{status}");
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

    #[test]
    #[cfg(unix)]
    fn test_parse_afl_cmdline() {
        use alloc::string::ToString;

        let mut mgr = SimpleEventManager::new(SimpleMonitor::new(|status| {
            println!("{status}");
        }));

        let mut executor =
            CommandExecutor::parse_afl_cmdline(["file".to_string(), "@@".to_string()], (), true)
                .unwrap();
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
