use core::marker::PhantomData;
use std::{
    fs::{File, OpenOptions},
    io::{self, prelude::*, SeekFrom},
    os::unix::{
        io::{AsRawFd, RawFd},
        process::CommandExt,
    },
    process::{Command, Stdio},
};

use crate::bolts::os::{dup2, pipes::Pipe};
use crate::{
    executors::{
        Executor, ExitKind, HasExecHooks, HasExecHooksTuple, HasObservers, HasObserversHooks,
    },
    inputs::{HasTargetBytes, Input},
    observers::ObserversTuple,
    Error,
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
            let memlimit: libc::rlim_t = memlimit << 20;
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

pub struct Forkserver {
    st_pipe: Pipe,
    ctl_pipe: Pipe,
    child_pid: u32,
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
            child_pid: 0,
            status: 0,
            last_run_timed_out: 0,
        })
    }

    #[must_use]
    pub fn last_run_timed_out(&self) -> i32 {
        self.last_run_timed_out
    }

    #[must_use]
    pub fn status(&self) -> i32 {
        self.status
    }

    #[must_use]
    pub fn child_pid(&self) -> u32 {
        self.child_pid
    }

    pub fn read_st(&mut self) -> Result<(usize, i32), io::Error> {
        let mut buf: [u8; 4] = [0u8; 4];

        let rlen = self.st_pipe.read(&mut buf)?;
        let val: i32 = i32::from_ne_bytes(buf);

        Ok((rlen, val))
    }

    pub fn write_ctl(&mut self, val: i32) -> Result<usize, io::Error> {
        let slen = self.ctl_pipe.write(&val.to_ne_bytes())?;

        Ok(slen)
    }
}

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
    pub fn new(target: String, arguments: Vec<String>, observers: OT) -> Result<Self, Error> {
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
}

impl<I, OT> Executor<I> for ForkserverExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    #[inline]
    fn run_target(&mut self, input: &I) -> Result<ExitKind, Error> {
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

        let (recv_len, pid) = self.forkserver.read_st()?;
        if recv_len != 4 {
            return Err(Error::Forkserver(
                "Unable to request new process from fork server (OOM?)".to_string(),
            ));
        }

        if pid <= 0 {
            return Err(Error::Forkserver(
                "Fork server is misbehaving (OOM?)".to_string(),
            ));
        }

        let (_, status) = self.forkserver.read_st()?;
        self.forkserver.status = status;

        if !libc::WIFSTOPPED(self.forkserver.status()) {
            self.forkserver.child_pid = 0;
        }

        if libc::WIFSIGNALED(self.forkserver.status()) {
            exit_kind = ExitKind::Crash;
        }

        Ok(exit_kind)
    }
}

impl<EM, I, OT, S, Z> HasExecHooks<EM, I, S, Z> for ForkserverExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
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
        let bin = "/usr/bin/echo".to_string();
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

        let executor =
            ForkserverExecutor::<NopInput, _>::new(bin, args, tuple_list!(edges_observer));
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
