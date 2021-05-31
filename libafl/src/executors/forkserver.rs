//! Expose an `Executor` based on a `Forkserver` in order to execute AFL/AFL++ binaries

use core::{marker::PhantomData, time::Duration};
use std::{
    fs::{File, OpenOptions},
    io::{self, prelude::*, ErrorKind, SeekFrom},
    os::unix::{
        io::{AsRawFd, RawFd},
        process::CommandExt,
    },
    process::{Command, Stdio},
};

use crate::{
    bolts::os::{dup2, pipes::Pipe},
    executors::{Executor, ExitKind, HasExecHooksTuple, HasObservers, HasObserversHooks},
    inputs::{HasTargetBytes, Input},
    observers::ObserversTuple,
    Error,
};
use nix::{
    sys::{
        select::{select, FdSet},
        signal::{kill, Signal},
        time::{TimeVal, TimeValLike},
    },
    unistd::Pid,
};

const FORKSRV_FD: i32 = 198;

// Configure the target. setlimit, setsid, pipe_stdin, I borrowed the code from Angora fuzzer
pub trait ConfigTarget {
    fn setsid(&mut self) -> &mut Self;
    fn setlimit(&mut self, memlimit: u64) -> &mut Self;
    fn setstdin(&mut self, fd: RawFd, use_stdin: bool) -> &mut Self;
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

pub struct OutFile {
    file: File,
}

impl OutFile {
    pub fn new(file_name: &str) -> Result<Self, Error> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(file_name)?;
        Ok(Self { file: f })
    }

    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    pub fn write_buf(&mut self, buf: &[u8]) {
        self.rewind();
        self.file.write_all(buf).unwrap();
        self.file.set_len(buf.len() as u64).unwrap();
        self.file.flush().unwrap();
        // Rewind again otherwise the target will not read stdin from the beginning
        self.rewind();
    }

    pub fn rewind(&mut self) {
        self.file.seek(SeekFrom::Start(0)).unwrap();
    }
}

/// The [`Forkserver`] is communication channel with a child process that forks on request of the fuzzer.
/// The communication happens via pipe.
pub struct Forkserver {
    st_pipe: Pipe,
    ctl_pipe: Pipe,
    child_pid: Pid,
    status: i32,
    last_run_timed_out: i32,
}

impl Forkserver {
    pub fn new(
        target: String,
        args: Vec<String>,
        out_filefd: RawFd,
        use_stdin: bool,
        memlimit: u64,
    ) -> Result<Self, Error> {
        let mut st_pipe = Pipe::new().unwrap();
        let mut ctl_pipe = Pipe::new().unwrap();

        match Command::new(target)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env("LD_BIND_LAZY", "1")
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
            Ok(_) => {}
            Err(_) => {
                return Err(Error::Forkserver(
                    "Could not spawn a forkserver!".to_string(),
                ));
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

    #[must_use]
    pub fn last_run_timed_out(&self) -> i32 {
        self.last_run_timed_out
    }

    pub fn set_last_run_timed_out(&mut self, last_run_timed_out: i32) {
        self.last_run_timed_out = last_run_timed_out;
    }

    #[must_use]
    pub fn status(&self) -> i32 {
        self.status
    }

    pub fn set_status(&mut self, status: i32) {
        self.status = status;
    }

    #[must_use]
    pub fn child_pid(&self) -> Pid {
        self.child_pid
    }

    pub fn set_child_pid(&mut self, child_pid: Pid) {
        self.child_pid = child_pid;
    }

    pub fn read_st(&mut self) -> Result<(usize, i32), Error> {
        let mut buf: [u8; 4] = [0u8; 4];

        let rlen = self.st_pipe.read(&mut buf)?;
        let val: i32 = i32::from_ne_bytes(buf);

        Ok((rlen, val))
    }

    pub fn write_ctl(&mut self, val: i32) -> Result<usize, Error> {
        let slen = self.ctl_pipe.write(&val.to_ne_bytes())?;

        Ok(slen)
    }

    pub fn read_st_timed(&mut self, timeout: &mut TimeVal) -> Result<Option<i32>, Error> {
        let mut buf: [u8; 4] = [0u8; 4];
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
        let mut copy = *timeout;
        readfds.insert(st_read);
        // We'll pass a copied timeout to keep the original timeout intact, because select updates timeout to indicate how much time was left. See select(2)
        let sret = select(
            Some(readfds.highest().unwrap() + 1),
            &mut readfds,
            None,
            None,
            &mut copy,
        )?;
        if sret > 0 {
            if let Err(_) = self.st_pipe.read_exact(&mut buf) {
                return Err(Error::Forkserver(
                    "Unable to communicate with fork server (OOM?)".to_string(),
                ));
            }

            let val: i32 = i32::from_ne_bytes(buf);
            Ok(Some(val))
        } else {
            Ok(None)
        }
    }
}

pub trait HasForkserver {
    fn forkserver(&self) -> &Forkserver;

    fn forkserver_mut(&mut self) -> &mut Forkserver;

    fn out_file(&self) -> &OutFile;

    fn out_file_mut(&mut self) -> &mut OutFile;
}

/// The timeout forkserver executor that wraps around the standard forkserver executor and sets a timeout before each run.
pub struct TimeoutForkserverExecutor<E> {
    executor: E,
    timeout: TimeVal,
}

impl<E> TimeoutForkserverExecutor<E> {
    pub fn new(executor: E, exec_tmout: Duration) -> Result<Self, Error> {
        let milli_sec = exec_tmout.as_millis() as i64;
        let timeout = TimeVal::milliseconds(milli_sec);
        Ok(Self { executor, timeout })
    }
}

impl<E, EM, I, S, Z> Executor<EM, I, S, Z> for TimeoutForkserverExecutor<E>
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

        self.executor
            .out_file_mut()
            .write_buf(&input.target_bytes().as_slice());

        let send_len = self
            .executor
            .forkserver_mut()
            .write_ctl(last_run_timed_out)?;
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
            .read_st_timed(&mut self.timeout)?
        {
            self.executor.forkserver_mut().set_status(status);
            if libc::WIFSIGNALED(self.executor.forkserver().status()) {
                exit_kind = ExitKind::Crash;
            }
        } else {
            self.executor.forkserver_mut().set_last_run_timed_out(1);

            // We need to kill the child in case he has timed out, or we can't get the correct pid in the next call to self.executor.forkserver_mut().read_st()?
            kill(self.executor.forkserver().child_pid(), Signal::SIGKILL).unwrap();
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
pub struct ForkserverExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    target: String,
    args: Vec<String>,
    out_file: OutFile,
    forkserver: Forkserver,
    observers: OT,
    phantom: PhantomData<I>,
}

impl<I, OT> ForkserverExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    pub fn new(target: String, arguments: &[String], observers: OT) -> Result<Self, Error> {
        let mut args = Vec::<String>::new();
        let mut use_stdin = true;
        let out_filename = ".cur_input".to_string();

        for item in arguments {
            if item == "@@" && use_stdin {
                use_stdin = false;
                args.push(out_filename.clone());
            } else {
                args.push(item.to_string());
            }
        }

        let out_file = OutFile::new(&out_filename)?;

        let mut forkserver = Forkserver::new(
            target.clone(),
            args.clone(),
            out_file.as_raw_fd(),
            use_stdin,
            0,
        )?;

        let (rlen, _) = forkserver.read_st()?; // Initial handshake, read 4-bytes hello message from the forkserver.

        match rlen {
            4 => {
                println!("All right - fork server is up.");
            }
            _ => {
                return Err(Error::Forkserver(
                    "Failed to start a forkserver".to_string(),
                ))
            }
        }

        Ok(Self {
            target,
            args,
            out_file,
            forkserver,
            observers,
            phantom: PhantomData,
        })
    }

    pub fn target(&self) -> &String {
        &self.target
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    pub fn forkserver(&self) -> &Forkserver {
        &self.forkserver
    }

    pub fn out_file(&self) -> &OutFile {
        &self.out_file
    }
}

impl<EM, I, OT, S, Z> Executor<EM, I, S, Z> for ForkserverExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
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
        self.out_file.write_buf(&input.target_bytes().as_slice());

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
        }

        self.forkserver.set_child_pid(Pid::from_raw(0));

        Ok(exit_kind)
    }
}

impl<I, OT> HasObservers<OT> for ForkserverExecutor<I, OT>
where
    I: Input + HasTargetBytes,
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

impl<EM, I, OT, S, Z> HasObserversHooks<EM, I, OT, S, Z> for ForkserverExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
{
}

impl<I, OT> HasForkserver for ForkserverExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
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
}

impl<E, OT> HasObservers<OT> for TimeoutForkserverExecutor<E>
where
    E: HasObservers<OT>,
    OT: ObserversTuple,
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

impl<E, EM, I, OT, S, Z> HasObserversHooks<EM, I, OT, S, Z> for TimeoutForkserverExecutor<E>
where
    E: HasObservers<OT>,
    I: Input,
    OT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
{
}

#[cfg(test)]
mod tests {
    use crate::{
        bolts::{
            shmem::{ShMem, ShMemProvider, StdShMemProvider},
            tuples::tuple_list,
        },
        executors::ForkserverExecutor,
        inputs::NopInput,
        observers::{ConstMapObserver, HitcountsMapObserver},
        Error,
    };
    #[test]
    fn test_forkserver() {
        const MAP_SIZE: usize = 65536;
        let bin = "echo";
        let args = vec![String::from("@@")];

        let mut shmem = StdShMemProvider::new()
            .unwrap()
            .new_map(MAP_SIZE as usize)
            .unwrap();
        shmem.write_to_env("__AFL_SHM_ID").unwrap();
        let mut shmem_map = shmem.map_mut();

        let edges_observer = HitcountsMapObserver::new(ConstMapObserver::<_, MAP_SIZE>::new(
            "shared_mem",
            &mut shmem_map,
        ));

        let executor = ForkserverExecutor::<NopInput, _>::new(
            bin.to_string(),
            &args,
            tuple_list!(edges_observer),
        );
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
