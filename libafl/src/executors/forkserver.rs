use core::marker::PhantomData;

use std::{
    fs::{File, OpenOptions},
    io::{prelude::*, SeekFrom},
    os::{
        raw::c_int,
        unix::{
            io::{AsRawFd, RawFd},
            process::CommandExt,
        },
    },
    process::{Command, Stdio},
};

use crate::bolts::shmem::{ShMemProvider, StdShMemProvider, ShMem};
use crate::{
    executors::{Executor, ExitKind, HasObservers, HasExecHooks},
    inputs::{HasTargetBytes, Input},
    observers::ObserversTuple,
    Error,
};

const FORKSRV_FD: i32 = 198;
const MAP_SIZE: i32 = 65536;
//configure the target. setlimit, setsid, pipe_stdin... , I borrowed the code from Angora fuzzer
//TODO: Better error handling.
pub trait ConfigTarget {
    fn setsid(&mut self) -> &mut Self;
    fn setlimit(&mut self, memlimit: u64) -> &mut Self;
    fn setstdin(&mut self, fd: Option<RawFd>) -> &mut Self;
    fn setpipe(&mut self, st_pipe: Pipe, ctl_pipe: Pipe) -> &mut Self;
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

    fn setpipe(&mut self, st_pipe: Pipe, ctl_pipe: Pipe) -> &mut Self {
        let func = move || {
            let ret = unsafe { libc::dup2(ctl_pipe.read_end, FORKSRV_FD) };
            if ret < 0 {
                panic!("dup2() failed");
            }
            let ret = unsafe { libc::dup2(st_pipe.write_end, FORKSRV_FD + 1) };
            if ret < 0 {
                panic!("dup2() failed");
            }
            unsafe {
                libc::close(ctl_pipe.read_end);
                libc::close(ctl_pipe.write_end);
                libc::close(st_pipe.read_end);
                libc::close(st_pipe.write_end);
            }
            Ok(())
        };
        unsafe { self.pre_exec(func) }
    }

    fn setstdin(&mut self, fd: Option<RawFd>) -> &mut Self {
        if fd.is_some() {
            let func = move || {
                let ret = unsafe { libc::dup2(fd.unwrap(), libc::STDIN_FILENO) };
                if ret < 0 {
                    panic!("dup2() failed");
                }
                unsafe { libc::close(fd.unwrap()) }; //fd gets automatically closed?
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

    pub fn write_buf(&mut self, buf: &Vec<u8>) {
        self.file.seek(SeekFrom::Start(0)).unwrap();
        self.file.write(buf).unwrap();
        self.file.set_len(buf.len() as u64).unwrap();
        self.file.flush().unwrap();
    }

    pub fn rewind(&mut self) {
        self.file.seek(SeekFrom::Start(0)).unwrap();
    }
}

#[derive(Debug, Clone)]
pub struct Pipe {
    read_end: RawFd,
    write_end: RawFd,
}

impl Pipe {
    fn new() -> Self {
        let mut fds = [-1 as c_int, -1 as c_int];
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if ret < 0 {
            panic!("pipe() failed");
        }
        Self {
            read_end: fds[0],
            write_end: fds[1],
        }
    }
}

pub struct Forkserver {
    st_pipe: Pipe,
    ctl_pipe: Pipe,
    pid: u32,
    last_run_timed_out: i32,
}

impl Forkserver {
    pub fn new(target: String, args: Vec<String>, out_file: String, use_stdin: bool, memlimit: u64) -> Self {
        //check if we'll use stdin

        let mut fd = None;
        if use_stdin{
            fd = Some(OutFile::new(&out_file).as_raw_fd());
        }

        let mut pid = 0;
        //create 2 pipes
        let st_pipe: Pipe = Pipe::new();
        let ctl_pipe: Pipe = Pipe::new();

        //setsid, setrlimit, direct stdin, set pipe, and finally fork.
        match Command::new(target)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env("LD_BIND_LAZY", "1")
            .setlimit(memlimit)
            .setsid()
            .setstdin(fd)
            .setpipe(st_pipe.clone(), ctl_pipe.clone())
            .spawn()
        {
            Ok(child) => {
                pid = child.id();
            },
            Err(_) => {
                panic!("Command::new() failed");
            }
        };
        //we'll close unneeded endpoints
        unsafe {
            libc::close(ctl_pipe.read_end);
            libc::close(st_pipe.write_end);
        }

        Self {
            st_pipe:st_pipe,
            ctl_pipe:ctl_pipe,
            pid: pid,
            last_run_timed_out:0,
        }
    }

    /*
    1. Check if @@ exists
    2. Open /dev/null
    3. pipe st_pipe and pipe ctl_pipe
    4. fork()
    5. setsid
    6. if outfile (file tu fuzz )exists,
        then stdin is dev/null
        else direct outfile to stdin
        and immediately close it
    7. stdout, stderr to dev/null
    8. ctl[0] to FORKSRV_FD, st[1] to FORKSRV_FD+1
    9. close ctl,st on child
    10. execve
    4':close ctl[0], st[1]
    */

    pub fn last_run_timed_out(&self) -> i32{
        self.last_run_timed_out
    }

    pub fn pid(&self) -> u32{
        self.pid
    }

    pub fn read_st(&self) -> (isize, i32){
        unsafe{
            let mut status : i32 = 0;
            let rlen = libc::read(
                self.st_pipe.read_end,
                (&mut status) as *mut libc::c_int as *mut libc::c_void,
                4,
            );
            (rlen, status)
        }
    }

    pub fn write_ctl(&self, mut val: i32) -> isize{
        unsafe{
            let slen = libc::write(
                self.ctl_pipe.write_end,
                (&mut val) as *mut libc::c_int as *mut libc::c_void,
                4,
            );
            slen
        }
    }
}

impl Drop for Forkserver{
    fn drop(&mut self){
        unsafe {
            libc::close(self.ctl_pipe.read_end);
            libc::close(self.ctl_pipe.write_end);
            libc::close(self.st_pipe.read_end);
            libc::close(self.st_pipe.write_end);
        }
    }
}

pub struct ForkserverExecutor<EM, I, OT, S>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    target: String,
    args: Vec<String>,
    use_stdin: bool,
    out_file: String,
    forkserver: Forkserver,
    observers: OT,
    phantom: PhantomData<(EM, I, S)>,
}

impl<EM, I, OT, S> ForkserverExecutor<EM, I, OT, S>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    pub fn new(bin: &'static str, argv: Vec<&'static str>, observers: OT) -> Result<Self, Error> {
        let target = bin.to_string();
        let mut args = Vec::<String>::new();
        let mut use_stdin = true;
        let out_file = format!("out-{}", 123456789); //TODO: replace it with a random number
        
        for item in argv{
            if item == "@@" && use_stdin {
                use_stdin = false; //only 1 @@ allowed.
                args.push(out_file.clone());
            }
            else{
                args.push(item.to_string());
            }
        }

        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();

        //shmem_set_up
        let shmem = StdShMemProvider::new().unwrap().new_map(MAP_SIZE as usize).unwrap();
        shmem.write_to_env("__AFL_SHM_ID")?;

        //forkserver
        let forkserver = Forkserver::new(target.clone(), args.clone(), out_file.clone(), use_stdin, 0);
        let (rlen, _) = forkserver.read_st();//initial handshake
        if rlen == 4{
            println!("Forkserver up!!");
        }

        Ok(Self {
            target,
            args,
            use_stdin,
            out_file,
            forkserver,
            observers,
            phantom: PhantomData,
        })
    }

    pub fn target(&self) -> &String {
        &self.target
    }

    pub fn args(&self) -> &Vec<String>{
        &self.args
    }

    pub fn forkserver(&self) -> &Forkserver{
        &self.forkserver
    }

}
impl<EM, I, OT, S> Executor<I> for ForkserverExecutor<EM, I, OT, S>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    #[inline]
    fn run_target(&mut self, _input: &I) -> Result<ExitKind, Error> {

        let slen = self.forkserver.write_ctl(self.forkserver().last_run_timed_out());
        if slen != 4{
            panic!("failed to request new process");
        }

        let (rlen, _data) = self.forkserver.read_st();
        if rlen != 4 {
            panic!("failed to request new process")
        }


        Ok(ExitKind::Ok)
    }
}

impl<EM, I, OT, S> HasExecHooks<EM, I, S> for ForkserverExecutor<EM, I, OT, S>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _event_mgr: &mut EM, input: &I) -> Result<(), Error>{
        //write to test case
        let mut out_file = OutFile::new(&self.out_file);
        out_file.write_buf(&input.target_bytes().as_slice().to_vec());
        //outfile gets automatically closed.
        Ok(())
    }

    fn post_exec(&mut self, _state: &mut S, _event_mgr: &mut EM, _input: &I) -> Result<(), Error>{
        Ok(())
    }
}

impl<EM, I, OT, S> HasObservers<OT> for ForkserverExecutor<EM, I, OT, S>
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

#[cfg(test)]
mod tests {

    use crate::executors::{OutFile, ForkserverExecutor, Forkserver, Executor};
    use crate::inputs::NopInput;
    #[test]
    fn test_forkserver() {
        let command = "/home/toka/work/aflsimple/test";
        let args = vec!["@@"];
        //let fd = OutFile::new("input_file");
        //let forkserver = Forkserver::new(command.to_string(), args.iter().map(|s| s.to_string()).collect(), Some(fd.as_raw_fd()), 0);
        let mut executors = ForkserverExecutor::<(), NopInput, (), ()>::new(command ,args, ()).unwrap();
        let nop = NopInput{};
        executors.run_target(&nop);
    }
}
