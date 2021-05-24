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
    corpus::Corpus,
    events::{EventFirer, EventRestarter},
    executors::{
        Executor, ExitKind, HasExecHooks, HasExecHooksTuple, HasObservers, HasObserversHooks,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::{HasTargetBytes, Input},
    observers::ObserversTuple,
    state::HasSolutions,
    Error,
};

const FORKSRV_FD: i32 = 198;
//configure the target. setlimit, setsid, pipe_stdin... , I borrowed the code from Angora fuzzer
//TODO: Better error handling.
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
                _ => {
                    panic!("dup2 failed\n");
                }
            }

            match dup2(st_write, FORKSRV_FD + 1) {
                Ok(_) => (),
                _ => {
                    panic!("dup2 failed\n");
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
                let ret = unsafe { libc::dup2(fd, libc::STDIN_FILENO) };
                if ret < 0 {
                    panic!("dup2() failed");
                }
                unsafe { libc::close(fd) }; //fd gets automatically closed?
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

            let ret = unsafe { libc::setrlimit(libc::RLIMIT_AS, &r) };
            if ret < 0 {
                panic!("setrlimit() failed");
            }
            let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &r0) };
            if ret < 0 {
                panic!("setrlimit() failed");
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
    pub fn new(file_name: &str) -> Self {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(file_name)
            .expect("Failed to open the input file");
        Self { file: f }
    }
    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    pub fn write_buf(&mut self, buf: &[u8]) {
        self.file.seek(SeekFrom::Start(0)).unwrap();
        self.file.write(buf).unwrap();
        self.file.set_len(buf.len() as u64).unwrap();
        self.file.flush().unwrap();
    }

    pub fn rewind(&mut self) {
        self.file.seek(SeekFrom::Start(0)).unwrap();
    }
}

pub struct Forkserver {
    st_pipe: Pipe,
    ctl_pipe: Pipe,
    child_pid: u32, //fuzzed program pid
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
    ) -> Self {
        //create 2 pipes
        let mut st_pipe = Pipe::new().unwrap();
        let mut ctl_pipe = Pipe::new().unwrap();

        //setsid, setrlimit, direct stdin, set pipe, and finally fork.
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
                panic!("Command::new() failed");
            }
        };

        //parent: we'll close unneeded endpoints
        ctl_pipe.close_read_end();
        st_pipe.close_write_end();

        Self {
            st_pipe: st_pipe,
            ctl_pipe: ctl_pipe,
            child_pid: 0,
            status: 0,
            last_run_timed_out: 0,
        }
    }

    pub fn last_run_timed_out(&self) -> i32 {
        self.last_run_timed_out
    }

    pub fn status(&self) -> i32 {
        self.status
    }

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
        let buf = val.to_ne_bytes();
        let slen = self.ctl_pipe.write(&buf)?;

        Ok(slen)
    }
}

pub struct ForkserverExecutor<I, OC, OF, OT, S>
where
    I: Input + HasTargetBytes,
    OC: Corpus<I>,
    OF: Feedback<I, S>,
    OT: ObserversTuple,
{
    target: String,
    args: Vec<String>,
    out_file: OutFile,
    forkserver: Forkserver,
    observers: OT,
    phantom: PhantomData<(OC, OF, I, S)>,
}

impl<I, OC, OF, OT, S> ForkserverExecutor<I, OC, OF, OT, S>
where
    I: Input + HasTargetBytes,
    OC: Corpus<I>,
    OF: Feedback<I, S>,
    OT: ObserversTuple,
{
    pub fn new(target: String, argv: Vec<String>, observers: OT) -> Result<Self, Error> {
        let mut args = Vec::<String>::new();
        let mut use_stdin = true;
        let out_filename = format!("out-{}", 123456789); //TODO: replace it with a random number

        for item in argv {
            if item == "@@" && use_stdin {
                use_stdin = false; //only 1 '@@' allowed.
                args.push(out_filename.clone());
            } else {
                args.push(item.to_string());
            }
        }

        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();

        let out_file = OutFile::new(&out_filename);

        //forkserver
        let mut forkserver = Forkserver::new(
            target.clone(),
            args.clone(),
            out_file.as_raw_fd(),
            use_stdin,
            0,
        );
        let (rlen, _) = forkserver.read_st()?; //initial handshake

        if rlen == 4 {
            println!("Forkserver up!!");
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

    pub fn args(&self) -> &Vec<String> {
        &self.args
    }

    pub fn forkserver(&self) -> &Forkserver {
        &self.forkserver
    }
}

impl<I, OC, OF, OT, S> Executor<I> for ForkserverExecutor<I, OC, OF, OT, S>
where
    I: Input + HasTargetBytes,
    OC: Corpus<I>,
    OF: Feedback<I, S>,
    OT: ObserversTuple,
{
    #[inline]
    fn run_target(&mut self, input: &I) -> Result<ExitKind, Error> {
        let mut exit_kind = ExitKind::Ok;

        // Write to test case
        self.out_file.write_buf(&input.target_bytes().as_slice());
        // outfile gets automatically closed.

        // let t1 = crate::bolts::os::current_time();
        let slen = self
            .forkserver
            .write_ctl(self.forkserver().last_run_timed_out())?;
        if slen != 4 {
            panic!("failed to request new process");
        }

        let (rlen, pid) = self.forkserver.read_st()?;
        if rlen != 4 {
            panic!("failed to request new process")
        }

        if pid <= 0 {
            panic!("forkserver is misbehaving");
        }
        //println!("pid: {:#?}",pid);

        //child running

        let (_, status) = self.forkserver.read_st()?;
        self.forkserver.status = status;

        // let t2 = crate::bolts::os::current_time();
        // println!("Exec time {} ns", (t2 - t1).as_nanos());

        if !libc::WIFSTOPPED(self.forkserver.status()) {
            self.forkserver.child_pid = 0;
        }

        if libc::WIFSIGNALED(self.forkserver.status()) {
            exit_kind = ExitKind::Crash;
        }

        //move the head back
        self.out_file.rewind();

        Ok(exit_kind)
    }
}

impl<EM, I, OC, OF, OT, S, Z> HasExecHooks<EM, I, S, Z> for ForkserverExecutor<I, OC, OF, OT, S>
where
    EM: EventFirer<I, S> + EventRestarter<S>,
    I: Input + HasTargetBytes,
    OC: Corpus<I>,
    OF: Feedback<I, S>,
    OT: ObserversTuple,
    S: HasSolutions<OC, I>,
    Z: HasObjective<I, OF, S>,
{
}

impl<I, OC, OF, OT, S> HasObservers<OT> for ForkserverExecutor<I, OC, OF, OT, S>
where
    I: Input + HasTargetBytes,
    OC: Corpus<I>,
    OT: ObserversTuple,
    OF: Feedback<I, S>,
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

impl<EM, I, OC, OF, OT, S, Z> HasObserversHooks<EM, I, OT, S, Z>
    for ForkserverExecutor<I, OC, OF, OT, S>
where
    I: Input + HasTargetBytes,
    OC: Corpus<I>,
    OF: Feedback<I, S>,
    OT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
{
}
