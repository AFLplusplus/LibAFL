//! Expose an `Executor` based on a `Forkserver` in order to execute AFL/AFL++ binaries

use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    time::Duration,
};
use std::{
    ffi::{OsStr, OsString},
    io::{self, prelude::*, ErrorKind},
    os::unix::{io::RawFd, process::CommandExt},
    path::Path,
    process::{Command, Stdio},
};

use crate::{
    bolts::{
        fs::{OutFile, OUTFILE_STD},
        os::{dup2, pipes::Pipe},
        shmem::{ShMem, ShMemProvider, StdShMemProvider},
        AsMutSlice, AsSlice,
    },
    executors::{Executor, ExitKind, HasObservers},
    inputs::{HasTargetBytes, Input},
    mutators::Tokens,
    observers::{get_asan_runtime_flags_with_log_path, ASANBacktraceObserver, ObserversTuple},
    Error,
};

use nix::{
    sys::{
        select::{pselect, FdSet},
        signal::{kill, SigSet, Signal},
        time::{TimeSpec, TimeValLike},
    },
    unistd::Pid,
};

const FORKSRV_FD: i32 = 198;
#[allow(clippy::cast_possible_wrap)]
const FS_OPT_ENABLED: i32 = 0x80000001_u32 as i32;
#[allow(clippy::cast_possible_wrap)]
const FS_OPT_SHDMEM_FUZZ: i32 = 0x01000000_u32 as i32;
#[allow(clippy::cast_possible_wrap)]
const FS_OPT_AUTODICT: i32 = 0x10000000_u32 as i32;
const SHMEM_FUZZ_HDR_SIZE: usize = 4;
const MAX_FILE: usize = 1024 * 1024;

/// Configure the target, `limit`, `setsid`, `pipe_stdin`, the code was borrowed from the [`Angora`](https://github.com/AngoraFuzzer/Angora) fuzzer
pub trait ConfigTarget {
    /// Sets the sid
    fn setsid(&mut self) -> &mut Self;
    /// Sets a mem limit
    fn setlimit(&mut self, memlimit: u64) -> &mut Self;
    /// Sets the stdin
    fn setstdin(&mut self, fd: RawFd, use_stdin: bool) -> &mut Self;
    /// Sets the AFL forkserver pipes
    fn setpipe(
        &mut self,
        st_read: RawFd,
        st_write: RawFd,
        ctl_read: RawFd,
        ctl_write: RawFd,
    ) -> &mut Self;
}

impl ConfigTarget for Command {
    fn setsid(&mut self) -> &mut Self {
        let func = move || {
            unsafe {
                libc::setsid();
            };
            Ok(())
        };
        unsafe { self.pre_exec(func) }
    }

    fn setpipe(
        &mut self,
        st_read: RawFd,
        st_write: RawFd,
        ctl_read: RawFd,
        ctl_write: RawFd,
    ) -> &mut Self {
        let func = move || {
            match dup2(ctl_read, FORKSRV_FD) {
                Ok(_) => (),
                Err(_) => {
                    return Err(io::Error::last_os_error());
                }
            }

            match dup2(st_write, FORKSRV_FD + 1) {
                Ok(_) => (),
                Err(_) => {
                    return Err(io::Error::last_os_error());
                }
            }
            unsafe {
                libc::close(st_read);
                libc::close(st_write);
                libc::close(ctl_read);
                libc::close(ctl_write);
            }
            Ok(())
        };
        unsafe { self.pre_exec(func) }
    }

    fn setstdin(&mut self, fd: RawFd, use_stdin: bool) -> &mut Self {
        if use_stdin {
            let func = move || {
                match dup2(fd, libc::STDIN_FILENO) {
                    Ok(_) => (),
                    Err(_) => {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            };
            unsafe { self.pre_exec(func) }
        } else {
            self
        }
    }

    #[allow(trivial_numeric_casts)]
    fn setlimit(&mut self, memlimit: u64) -> &mut Self {
        if memlimit == 0 {
            return self;
        }
        let func = move || {
            let memlimit: libc::rlim_t = (memlimit as libc::rlim_t) << 20;
            let r = libc::rlimit {
                rlim_cur: memlimit,
                rlim_max: memlimit,
            };
            let r0 = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };

            #[cfg(target_os = "openbsd")]
            let mut ret = unsafe { libc::setrlimit(libc::RLIMIT_RSS, &r) };
            #[cfg(not(target_os = "openbsd"))]
            let mut ret = unsafe { libc::setrlimit(libc::RLIMIT_AS, &r) };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &r0) };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        };
        unsafe { self.pre_exec(func) }
    }
}

/// The [`Forkserver`] is communication channel with a child process that forks on request of the fuzzer.
/// The communication happens via pipe.
#[derive(Debug)]
pub struct Forkserver {
    st_pipe: Pipe,
    ctl_pipe: Pipe,
    child_pid: Pid,
    status: i32,
    last_run_timed_out: i32,
}

impl Forkserver {
    /// Create a new [`Forkserver`]
    pub fn new(
        target: OsString,
        args: Vec<OsString>,
        envs: Vec<(OsString, OsString)>,
        out_filefd: RawFd,
        use_stdin: bool,
        memlimit: u64,
        debug_output: bool,
    ) -> Result<Self, Error> {
        let mut st_pipe = Pipe::new().unwrap();
        let mut ctl_pipe = Pipe::new().unwrap();

        let (stdout, stderr) = if debug_output {
            (Stdio::inherit(), Stdio::inherit())
        } else {
            (Stdio::null(), Stdio::null())
        };

        match Command::new(target)
            .args(args)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .env("LD_BIND_LAZY", "1")
            .env("ASAN_OPTIONS", get_asan_runtime_flags_with_log_path())
            .envs(envs)
            .setlimit(memlimit)
            .setsid()
            .setstdin(out_filefd, use_stdin)
            .setpipe(
                st_pipe.read_end().unwrap(),
                st_pipe.write_end().unwrap(),
                ctl_pipe.read_end().unwrap(),
                ctl_pipe.write_end().unwrap(),
            )
            .spawn()
        {
            Ok(_) => (),
            Err(err) => {
                return Err(Error::Forkserver(format!(
                    "Could not spawn the forkserver: {:#?}",
                    err
                )))
            }
        };

        // Ctl_pipe.read_end and st_pipe.write_end are unnecessary for the parent, so we'll close them
        ctl_pipe.close_read_end();
        st_pipe.close_write_end();

        Ok(Self {
            st_pipe,
            ctl_pipe,
            child_pid: Pid::from_raw(0),
            status: 0,
            last_run_timed_out: 0,
        })
    }

    /// If the last run timed out
    #[must_use]
    pub fn last_run_timed_out(&self) -> i32 {
        self.last_run_timed_out
    }

    /// Sets if the last run timed out
    pub fn set_last_run_timed_out(&mut self, last_run_timed_out: i32) {
        self.last_run_timed_out = last_run_timed_out;
    }

    /// The status
    #[must_use]
    pub fn status(&self) -> i32 {
        self.status
    }

    /// Sets the status
    pub fn set_status(&mut self, status: i32) {
        self.status = status;
    }

    /// The child pid
    #[must_use]
    pub fn child_pid(&self) -> Pid {
        self.child_pid
    }

    /// Set the child pid
    pub fn set_child_pid(&mut self, child_pid: Pid) {
        self.child_pid = child_pid;
    }

    /// Read from the st pipe
    pub fn read_st(&mut self) -> Result<(usize, i32), Error> {
        let mut buf: [u8; 4] = [0_u8; 4];

        let rlen = self.st_pipe.read(&mut buf)?;
        let val: i32 = i32::from_ne_bytes(buf);
        Ok((rlen, val))
    }

    /// Read bytes of any length from the st pipe
    pub fn read_st_size(&mut self, size: usize) -> Result<(usize, Vec<u8>), Error> {
        let mut buf = vec![0; size];

        let rlen = self.st_pipe.read(&mut buf)?;
        Ok((rlen, buf))
    }

    /// Write to the ctl pipe
    pub fn write_ctl(&mut self, val: i32) -> Result<usize, Error> {
        let slen = self.ctl_pipe.write(&val.to_ne_bytes())?;

        Ok(slen)
    }

    /// Read a message from the child process.
    pub fn read_st_timed(&mut self, timeout: &TimeSpec) -> Result<Option<i32>, Error> {
        let mut buf: [u8; 4] = [0_u8; 4];
        let st_read = match self.st_pipe.read_end() {
            Some(fd) => fd,
            None => {
                return Err(Error::File(io::Error::new(
                    ErrorKind::BrokenPipe,
                    "Read pipe end was already closed",
                )));
            }
        };
        let mut readfds = FdSet::new();
        readfds.insert(st_read);
        // We'll pass a copied timeout to keep the original timeout intact, because select updates timeout to indicate how much time was left. See select(2)
        let sret = pselect(
            Some(readfds.highest().unwrap() + 1),
            &mut readfds,
            None,
            None,
            Some(timeout),
            Some(&SigSet::empty()),
        )?;
        if sret > 0 {
            if self.st_pipe.read_exact(&mut buf).is_ok() {
                let val: i32 = i32::from_ne_bytes(buf);
                Ok(Some(val))
            } else {
                Err(Error::Forkserver(
                    "Unable to communicate with fork server (OOM?)".to_string(),
                ))
            }
        } else {
            Ok(None)
        }
    }
}

/// A struct that has a forkserver
pub trait HasForkserver {
    /// The [`ShMemProvider`] used for this forkserver's map
    type SP: ShMemProvider;

    /// The forkserver
    fn forkserver(&self) -> &Forkserver;

    /// The forkserver, mutable
    fn forkserver_mut(&mut self) -> &mut Forkserver;

    /// The file the forkserver is reading from
    fn out_file(&self) -> &OutFile;

    /// The file the forkserver is reading from, mutable
    fn out_file_mut(&mut self) -> &mut OutFile;

    /// The map of the fuzzer
    fn shmem(&self) -> &Option<<<Self as HasForkserver>::SP as ShMemProvider>::ShMem>;

    /// The map of the fuzzer, mutable
    fn shmem_mut(&mut self) -> &mut Option<<<Self as HasForkserver>::SP as ShMemProvider>::ShMem>;
}

/// The timeout forkserver executor that wraps around the standard forkserver executor and sets a timeout before each run.
#[derive(Debug)]
pub struct TimeoutForkserverExecutor<E: Debug> {
    executor: E,
    timeout: TimeSpec,
    signal: Signal,
}

impl<E: Debug> TimeoutForkserverExecutor<E> {
    /// Create a new [`TimeoutForkserverExecutor`]
    pub fn new(executor: E, exec_tmout: Duration) -> Result<Self, Error> {
        let signal = Signal::SIGKILL;
        Self::with_signal(executor, exec_tmout, signal)
    }

    /// Create a new [`TimeoutForkserverExecutor`] that sends a user-defined signal to the timed-out process
    pub fn with_signal(executor: E, exec_tmout: Duration, signal: Signal) -> Result<Self, Error> {
        let milli_sec = exec_tmout.as_millis() as i64;
        let timeout = TimeSpec::milliseconds(milli_sec);
        Ok(Self {
            executor,
            timeout,
            signal,
        })
    }
}

impl<E: Debug, EM, I, S, Z> Executor<EM, I, S, Z> for TimeoutForkserverExecutor<E>
where
    I: Input + HasTargetBytes,
    E: Executor<EM, I, S, Z> + HasForkserver,
{
    #[inline]
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        let mut exit_kind = ExitKind::Ok;

        let last_run_timed_out = self.executor.forkserver().last_run_timed_out();

        match &mut self.executor.shmem_mut() {
            Some(shmem) => {
                let target_bytes = input.target_bytes();
                let size = target_bytes.as_slice().len();
                let size_in_bytes = size.to_ne_bytes();
                // The first four bytes tells the size of the shmem.
                shmem.as_mut_slice()[..4].copy_from_slice(&size_in_bytes[..4]);
                shmem.as_mut_slice()[SHMEM_FUZZ_HDR_SIZE..(SHMEM_FUZZ_HDR_SIZE + size)]
                    .copy_from_slice(target_bytes.as_slice());
            }
            None => {
                self.executor
                    .out_file_mut()
                    .write_buf(input.target_bytes().as_slice())?;
            }
        }

        let send_len = self
            .executor
            .forkserver_mut()
            .write_ctl(last_run_timed_out)?;

        self.executor.forkserver_mut().set_last_run_timed_out(0);

        if send_len != 4 {
            return Err(Error::Forkserver(
                "Unable to request new process from fork server (OOM?)".to_string(),
            ));
        }

        let (recv_pid_len, pid) = self.executor.forkserver_mut().read_st()?;
        if recv_pid_len != 4 {
            return Err(Error::Forkserver(
                "Unable to request new process from fork server (OOM?)".to_string(),
            ));
        }

        if pid <= 0 {
            return Err(Error::Forkserver(
                "Fork server is misbehaving (OOM?)".to_string(),
            ));
        }

        self.executor
            .forkserver_mut()
            .set_child_pid(Pid::from_raw(pid));

        if let Some(status) = self
            .executor
            .forkserver_mut()
            .read_st_timed(&self.timeout)?
        {
            self.executor.forkserver_mut().set_status(status);
            if libc::WIFSIGNALED(self.executor.forkserver().status()) {
                exit_kind = ExitKind::Crash;
            }
        } else {
            self.executor.forkserver_mut().set_last_run_timed_out(1);

            // We need to kill the child in case he has timed out, or we can't get the correct pid in the next call to self.executor.forkserver_mut().read_st()?
            let _ = kill(self.executor.forkserver().child_pid(), self.signal);
            let (recv_status_len, _) = self.executor.forkserver_mut().read_st()?;
            if recv_status_len != 4 {
                return Err(Error::Forkserver(
                    "Could not kill timed-out child".to_string(),
                ));
            }
            exit_kind = ExitKind::Timeout;
        }

        self.executor
            .forkserver_mut()
            .set_child_pid(Pid::from_raw(0));

        Ok(exit_kind)
    }
}

/// This [`Executor`] can run binaries compiled for AFL/AFL++ that make use of a forkserver.
/// Shared memory feature is also available, but you have to set things up in your code.
/// Please refer to AFL++'s docs. <https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md>
pub struct ForkserverExecutor<I, OT, S, SP>
where
    OT: Debug,
    SP: ShMemProvider,
{
    target: OsString,
    args: Vec<OsString>,
    out_file: OutFile,
    forkserver: Forkserver,
    observers: OT,
    map: Option<SP::ShMem>,
    phantom: PhantomData<(I, S)>,
    /// Cache that indicates if we have a asan observer registered.
    has_asan_observer: Option<bool>,
}

impl<I, OT, S, SP> Debug for ForkserverExecutor<I, OT, S, SP>
where
    OT: Debug,
    SP: ShMemProvider,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForkserverExecutor")
            .field("target", &self.target)
            .field("args", &self.args)
            .field("out_file", &self.out_file)
            .field("forkserver", &self.forkserver)
            .field("observers", &self.observers)
            .field("map", &self.map)
            .finish()
    }
}

impl ForkserverExecutor<(), (), (), StdShMemProvider> {
    /// Builder for `ForkserverExecutor`
    #[must_use]
    pub fn builder() -> ForkserverExecutorBuilder<'static, StdShMemProvider> {
        ForkserverExecutorBuilder::new()
    }
}

impl<I, OT, S, SP> ForkserverExecutor<I, OT, S, SP>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple<I, S>,
    SP: ShMemProvider,
{
    /// The `target` binary that's going to run.
    pub fn target(&self) -> &OsString {
        &self.target
    }

    /// The `args` used for the binary.
    pub fn args(&self) -> &[OsString] {
        &self.args
    }

    /// The [`Forkserver`] instance.
    pub fn forkserver(&self) -> &Forkserver {
        &self.forkserver
    }

    /// The [`OutFile`] used by this [`Executor`].
    pub fn out_file(&self) -> &OutFile {
        &self.out_file
    }
}

/// The builder for `ForkserverExecutor`
#[derive(Debug)]
pub struct ForkserverExecutorBuilder<'a, SP> {
    program: Option<OsString>,
    arguments: Vec<OsString>,
    envs: Vec<(OsString, OsString)>,
    debug_child: bool,
    use_stdin: bool,
    autotokens: Option<&'a mut Tokens>,
    out_filename: Option<OsString>,
    shmem_provider: Option<&'a mut SP>,
}

impl<'a, SP> ForkserverExecutorBuilder<'a, SP> {
    /// Builds `ForkserverExecutor`.
    #[allow(clippy::pedantic)]
    pub fn build<I, OT, S>(
        &mut self,
        observers: OT,
    ) -> Result<ForkserverExecutor<I, OT, S, SP>, Error>
    where
        I: Input + HasTargetBytes,
        OT: ObserversTuple<I, S>,
        SP: ShMemProvider,
    {
        let out_filename = match &self.out_filename {
            Some(name) => name.clone(),
            None => OsString::from(".cur_input"),
        };

        let out_file = OutFile::create(&out_filename)?;

        let map = match &mut self.shmem_provider {
            None => None,
            Some(provider) => {
                // setup shared memory
                let mut shmem = provider.new_shmem(MAX_FILE + SHMEM_FUZZ_HDR_SIZE)?;
                shmem.write_to_env("__AFL_SHM_FUZZ_ID")?;

                let size_in_bytes = (MAX_FILE + SHMEM_FUZZ_HDR_SIZE).to_ne_bytes();
                shmem.as_mut_slice()[..4].clone_from_slice(&size_in_bytes[..4]);
                Some(shmem)
            }
        };

        let (target, mut forkserver) = match &self.program {
            Some(t) => {
                let forkserver = Forkserver::new(
                    t.clone(),
                    self.arguments.clone(),
                    self.envs.clone(),
                    out_file.as_raw_fd(),
                    self.use_stdin,
                    0,
                    self.debug_child,
                )?;

                (t.clone(), forkserver)
            }
            None => {
                return Err(Error::IllegalArgument(
                    "ForkserverExecutorBuilder::build: target file not found".to_string(),
                ))
            }
        };

        let (rlen, status) = forkserver.read_st()?; // Initial handshake, read 4-bytes hello message from the forkserver.

        if rlen != 4 {
            return Err(Error::Forkserver(
                "Failed to start a forkserver".to_string(),
            ));
        }
        println!("All right - fork server is up.");
        // If forkserver is responding, we then check if there's any option enabled.
        if status & FS_OPT_ENABLED == FS_OPT_ENABLED {
            let mut send_status = FS_OPT_ENABLED;

            if (status & FS_OPT_SHDMEM_FUZZ == FS_OPT_SHDMEM_FUZZ) && map.is_some() {
                println!("Using SHARED MEMORY FUZZING feature.");
                send_status |= FS_OPT_SHDMEM_FUZZ;
            }

            if (status & FS_OPT_AUTODICT == FS_OPT_AUTODICT) && self.autotokens.is_some() {
                println!("Using AUTODICT feature");
                send_status |= FS_OPT_AUTODICT;
            }

            let send_len = forkserver.write_ctl(send_status)?;
            if send_len != 4 {
                return Err(Error::Forkserver(
                    "Writing to forkserver failed.".to_string(),
                ));
            }

            if (send_status & FS_OPT_AUTODICT) == FS_OPT_AUTODICT {
                let (read_len, dict_size) = forkserver.read_st()?;
                if read_len != 4 {
                    return Err(Error::Forkserver(
                        "Reading from forkserver failed.".to_string(),
                    ));
                }

                if !(2..=0xffffff).contains(&dict_size) {
                    return Err(Error::Forkserver(
                        "Dictionary has an illegal size".to_string(),
                    ));
                }

                println!("Autodict size {:x}", dict_size);

                let (rlen, buf) = forkserver.read_st_size(dict_size as usize)?;

                if rlen != dict_size as usize {
                    return Err(Error::Forkserver(
                        "Failed to load autodictionary".to_string(),
                    ));
                }

                if let Some(t) = &mut self.autotokens {
                    t.parse_autodict(&buf, dict_size as usize);
                }
            }
        } else {
            println!("Forkserver Options are not available.");
        }

        println!(
            "ForkserverExecutor: program: {:?}, arguments: {:?}, use_stdin: {:?}",
            target,
            self.arguments.clone(),
            self.use_stdin
        );

        Ok(ForkserverExecutor {
            target,
            args: self.arguments.clone(),
            out_file,
            forkserver,
            observers,
            map,
            phantom: PhantomData,
            has_asan_observer: None, // initialized on first use
        })
    }
}

impl<'a> ForkserverExecutorBuilder<'a, StdShMemProvider> {
    /// Creates a new `AFL`-style [`ForkserverExecutor`] with the given target, arguments and observers.
    /// This is the builder for `ForkserverExecutor`
    /// This Forkserver will attempt to provide inputs over shared mem when `shmem_provider` is given.
    /// Else this forkserver will try to write the input to `.cur_input` file.
    /// If `debug_child` is set, the child will print to `stdout`/`stderr`.
    #[must_use]
    pub fn new() -> ForkserverExecutorBuilder<'a, StdShMemProvider> {
        ForkserverExecutorBuilder {
            program: None,
            arguments: vec![],
            envs: vec![],
            debug_child: false,
            use_stdin: true,
            autotokens: None,
            out_filename: None,
            shmem_provider: None,
        }
    }

    /// The harness
    #[must_use]
    pub fn program<O>(mut self, program: O) -> Self
    where
        O: AsRef<OsStr>,
    {
        self.program = Some(program.as_ref().to_owned());
        self
    }

    /// Adds an argument to the harness's commandline
    #[must_use]
    pub fn arg<O>(mut self, arg: O) -> Self
    where
        O: AsRef<OsStr>,
    {
        self.arguments.push(arg.as_ref().to_owned());
        self
    }

    /// Adds arguments to the harness's commandline
    #[must_use]
    pub fn args<IT, O>(mut self, args: IT) -> Self
    where
        IT: IntoIterator<Item = O>,
        O: AsRef<OsStr>,
    {
        let mut res = vec![];
        for arg in args {
            res.push(arg.as_ref().to_owned());
        }
        self.arguments.append(&mut res);
        self
    }

    /// Adds an environmental var to the harness's commandline
    #[must_use]
    pub fn env<K, V>(mut self, key: K, val: V) -> Self
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.envs
            .push((key.as_ref().to_owned(), val.as_ref().to_owned()));
        self
    }

    /// Adds environmental vars to the harness's commandline
    #[must_use]
    pub fn envs<IT, K, V>(mut self, vars: IT) -> Self
    where
        IT: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        let mut res = vec![];
        for (ref key, ref val) in vars {
            res.push((key.as_ref().to_owned(), val.as_ref().to_owned()));
        }
        self.envs.append(&mut res);
        self
    }

    #[must_use]
    /// Place the input at this position and set the filename for the input.
    pub fn arg_input_file<P: AsRef<Path>>(self, path: P) -> Self {
        let mut moved = self.arg(path.as_ref());
        moved.out_filename = Some(path.as_ref().as_os_str().to_os_string());
        moved
    }

    #[must_use]
    /// Place the input at this position and set the default filename for the input.
    pub fn arg_input_file_std(self) -> Self {
        self.arg_input_file(OUTFILE_STD)
    }

    #[must_use]
    /// Parse afl style command line
    pub fn parse_afl_cmdline<IT, O>(mut self, args: IT) -> Self
    where
        IT: IntoIterator<Item = O>,
        O: AsRef<OsStr>,
    {
        let mut res = vec![];
        let mut use_stdin = true;

        for item in args {
            if item.as_ref() == "@@" && use_stdin {
                use_stdin = false;
                res.push(OsString::from(".cur_input"));
            } else if let Some(name) = &self.out_filename {
                if name == item.as_ref() && use_stdin {
                    use_stdin = false;
                    res.push(name.clone());
                } else {
                    res.push(item.as_ref().to_os_string());
                }
            } else {
                res.push(item.as_ref().to_os_string());
            }
        }

        self.arguments = res;
        self.use_stdin = use_stdin;
        self
    }

    #[must_use]
    /// If `debug_child` is set, the child will print to `stdout`/`stderr`.
    pub fn debug_child(mut self, debug_child: bool) -> Self {
        self.debug_child = debug_child;
        self
    }

    /// Use autodict?
    #[must_use]
    pub fn autotokens(mut self, tokens: &'a mut Tokens) -> Self {
        self.autotokens = Some(tokens);
        self
    }

    /// Shmem provider for forkserver's shared memory testcase feature.
    pub fn shmem_provider<SP: ShMemProvider>(
        self,
        shmem_provider: &'a mut SP,
    ) -> ForkserverExecutorBuilder<'a, SP> {
        ForkserverExecutorBuilder {
            program: self.program,
            arguments: self.arguments,
            envs: self.envs,
            debug_child: self.debug_child,
            use_stdin: self.use_stdin,
            autotokens: self.autotokens,
            out_filename: self.out_filename,
            shmem_provider: Some(shmem_provider),
        }
    }
}

impl<'a> Default for ForkserverExecutorBuilder<'a, StdShMemProvider> {
    fn default() -> Self {
        Self::new()
    }
}

impl<EM, I, OT, S, SP, Z> Executor<EM, I, S, Z> for ForkserverExecutor<I, OT, S, SP>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple<I, S>,
    SP: ShMemProvider,
{
    #[inline]
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        let mut exit_kind = ExitKind::Ok;

        // Write to testcase
        match &mut self.map {
            Some(map) => {
                let target_bytes = input.target_bytes();
                let size = target_bytes.as_slice().len();
                let size_in_bytes = size.to_ne_bytes();
                // The first four bytes tells the size of the shmem.
                map.as_mut_slice()[..4].copy_from_slice(&size_in_bytes[..4]);
                map.as_mut_slice()[SHMEM_FUZZ_HDR_SIZE..(SHMEM_FUZZ_HDR_SIZE + size)]
                    .copy_from_slice(target_bytes.as_slice());
            }
            None => {
                self.out_file.write_buf(input.target_bytes().as_slice())?;
            }
        }

        let send_len = self
            .forkserver
            .write_ctl(self.forkserver().last_run_timed_out())?;
        if send_len != 4 {
            return Err(Error::Forkserver(
                "Unable to request new process from fork server (OOM?)".to_string(),
            ));
        }

        let (recv_pid_len, pid) = self.forkserver.read_st()?;
        if recv_pid_len != 4 {
            return Err(Error::Forkserver(
                "Unable to request new process from fork server (OOM?)".to_string(),
            ));
        }

        if pid <= 0 {
            return Err(Error::Forkserver(
                "Fork server is misbehaving (OOM?)".to_string(),
            ));
        }

        self.forkserver.set_child_pid(Pid::from_raw(pid));

        let (recv_status_len, status) = self.forkserver.read_st()?;
        if recv_status_len != 4 {
            return Err(Error::Forkserver(
                "Unable to communicate with fork server (OOM?)".to_string(),
            ));
        }

        self.forkserver.set_status(status);

        if libc::WIFSIGNALED(self.forkserver.status()) {
            exit_kind = ExitKind::Crash;
            if self.has_asan_observer.is_none() {
                self.has_asan_observer = Some(
                    self.observers()
                        .match_name::<ASANBacktraceObserver>("ASANBacktraceObserver")
                        .is_some(),
                );
            }
            if self.has_asan_observer.unwrap() {
                self.observers_mut()
                    .match_name_mut::<ASANBacktraceObserver>("ASANBacktraceObserver")
                    .unwrap()
                    .parse_asan_output_from_asan_log_file(pid)?;
            }
        }

        self.forkserver.set_child_pid(Pid::from_raw(0));

        Ok(exit_kind)
    }
}

impl<I, OT, S, SP> HasObservers<I, OT, S> for ForkserverExecutor<I, OT, S, SP>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple<I, S>,
    SP: ShMemProvider,
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

impl<I, OT, S, SP> HasForkserver for ForkserverExecutor<I, OT, S, SP>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple<I, S>,
    SP: ShMemProvider,
{
    type SP = SP;

    #[inline]
    fn forkserver(&self) -> &Forkserver {
        &self.forkserver
    }

    #[inline]
    fn forkserver_mut(&mut self) -> &mut Forkserver {
        &mut self.forkserver
    }

    #[inline]
    fn out_file(&self) -> &OutFile {
        &self.out_file
    }

    #[inline]
    fn out_file_mut(&mut self) -> &mut OutFile {
        &mut self.out_file
    }

    #[inline]
    fn shmem(&self) -> &Option<SP::ShMem> {
        &self.map
    }

    #[inline]
    fn shmem_mut(&mut self) -> &mut Option<SP::ShMem> {
        &mut self.map
    }
}

impl<E, I, OT, S> HasObservers<I, OT, S> for TimeoutForkserverExecutor<E>
where
    E: HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S>,
{
    #[inline]
    fn observers(&self) -> &OT {
        self.executor.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        self.executor.observers_mut()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        bolts::{
            shmem::{ShMem, ShMemProvider, StdShMemProvider},
            tuples::tuple_list,
            AsMutSlice,
        },
        executors::forkserver::ForkserverExecutorBuilder,
        inputs::NopInput,
        observers::{ConstMapObserver, HitcountsMapObserver},
        Error,
    };
    use serial_test::serial;
    use std::ffi::OsString;
    #[test]
    #[serial]
    fn test_forkserver() {
        const MAP_SIZE: usize = 65536;
        let bin = OsString::from("echo");
        let args = vec![OsString::from("@@")];

        let mut shmem_provider = StdShMemProvider::new().unwrap();

        let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
        shmem.write_to_env("__AFL_SHM_ID").unwrap();
        let shmem_buf = shmem.as_mut_slice();

        let edges_observer = HitcountsMapObserver::new(ConstMapObserver::<_, MAP_SIZE>::new(
            "shared_mem",
            shmem_buf,
        ));

        let executor = ForkserverExecutorBuilder::new()
            .program(bin)
            .args(&args)
            .debug_child(false)
            .shmem_provider(&mut shmem_provider)
            .build::<NopInput, _, ()>(tuple_list!(edges_observer));

        // Since /usr/bin/echo is not a instrumented binary file, the test will just check if the forkserver has failed at the initial handshake
        let result = match executor {
            Ok(_) => true,
            Err(e) => match e {
                Error::Forkserver(s) => s == "Failed to start a forkserver",
                _ => false,
            },
        };
        assert!(result);
    }
}
