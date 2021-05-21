use core::marker::PhantomData;
use std::{
    fs::{File, OpenOptions},
    io::{prelude::*, SeekFrom, self},
    os::{
        unix::{
            io::{AsRawFd, RawFd},
            process::CommandExt,
        },
    },
    process::{Command, Stdio},
};

use crate::bolts::{shmem::{ShMemProvider, StdShMemProvider, ShMem}, os::pipes::Pipe, os::dup2};
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
    fn setstdin(&mut self, fd: RawFd, use_stdin:bool) -> &mut Self;
    fn setpipe(&mut self, st_read: RawFd, st_write: RawFd, ctl_read: RawFd, ctl_write: RawFd) -> &mut Self;
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

    fn setpipe(&mut self, st_read: RawFd, st_write: RawFd, ctl_read: RawFd, ctl_write: RawFd) -> &mut Self {
        let func = move || {

            match dup2(ctl_read, FORKSRV_FD){
                Ok(_) => (),
                _ => {
                    panic!("dup2 failed\n");
                }
            }

            match dup2(st_write, FORKSRV_FD + 1){
                Ok(_) => (),
                _ => {
                    panic!("dup2 failed\n");
                }
            }
            unsafe{
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


pub struct Forkserver {
    st_pipe: Pipe,
    ctl_pipe: Pipe,
    pid: u32, //forkserver pid
    child_pid: u32, //fuzzed program pid
    status: i32,
    last_run_timed_out: i32,
}


impl Forkserver {
    pub fn new(target: String, args: Vec<String>, out_filefd: RawFd, use_stdin: bool, memlimit: u64) -> Self {
        //check if we'll use stdin


        let mut pid = 0;
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
            .setpipe(st_pipe.read_end().unwrap(), st_pipe.write_end().unwrap(), ctl_pipe.read_end().unwrap(), ctl_pipe.write_end().unwrap())
            .spawn()
        {
            Ok(child) => {
                pid = child.id();
            },
            Err(_) => {
                panic!("Command::new() failed");
            }
        };


        //parent: we'll close unneeded endpoints
        ctl_pipe.close_read_end();
        st_pipe.close_write_end();

        Self {
            st_pipe:st_pipe,
            ctl_pipe:ctl_pipe,
            pid: pid,
            child_pid: 0,
            status: 0,
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

    pub fn status(&self) -> i32{
        self.status
    }

    pub fn child_pid(&self) -> u32{
        self.child_pid
    }

    pub fn read_st(&mut self) -> Result<(usize, i32), io::Error>{
        let mut buf : [u8; 4] = [0u8; 4];

        let rlen = self.st_pipe.read(&mut buf)?;
        let val : i32 = i32::from_ne_bytes(buf);

        Ok((rlen, val))
    }

    pub fn write_ctl(&mut self, val: i32) -> Result<usize, io::Error>{
        let buf = val.to_ne_bytes();
        let slen = self.ctl_pipe.write(&buf)?;

        Ok(slen)
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
    out_file: OutFile,
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
        let out_filename = format!("out-{}", 123456789); //TODO: replace it with a random number
        
        for item in argv{
            if item == "@@" && use_stdin {
                use_stdin = false; //only 1 @@ allowed.
                args.push(out_filename.clone());
            }
            else{
                args.push(item.to_string());
            }
        }

        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();

        //shmem_set_up
        let shmem = StdShMemProvider::new().unwrap().new_map(MAP_SIZE as usize).unwrap();
        shmem.write_to_env("__AFL_SHM_ID")?;

        let out_file = OutFile::new(&out_filename);

        //forkserver
        let mut forkserver = Forkserver::new(target.clone(), args.clone(), out_file.as_raw_fd(), use_stdin, 0);
        let (rlen, _) = forkserver.read_st()?;//initial handshake

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

        let slen = self.forkserver.write_ctl(self.forkserver().last_run_timed_out())?;
        if slen != 4{
            panic!("failed to request new process");
        }


        let (rlen, pid) = self.forkserver.read_st()?;
        if rlen != 4 {
            panic!("failed to request new process")
        }
        if pid <= 0 {
            panic!("forkserver is misbehaving");
        }
        println!("pid: {:#?}",pid);

        //child running
        let (_, status) = self.forkserver.read_st()?;
        self.forkserver.status = status;

        Ok(ExitKind::Ok)
    }
}

impl<EM, I, OT, S, Z> HasExecHooks<EM, I, S, Z> for ForkserverExecutor<EM, I, OT, S>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    #[inline]
    fn pre_exec(&mut self, _fuzzer:&mut Z, _state: &mut S, _event_mgr: &mut EM, input: &I) -> Result<(), Error>{
        //write to test case
        self.out_file.write_buf(&input.target_bytes().as_slice().to_vec());
        //outfile gets automatically closed.
        Ok(())
    }

    fn post_exec(&mut self, _fuzzer:&mut Z, _state: &mut S, _event_mgr: &mut EM, _input: &I) -> Result<(), Error>{

        if !libc::WIFSTOPPED(self.forkserver.status()) {
            self.forkserver.child_pid = 0;
        }

        //move the head back
        self.out_file.rewind();

        if(libc::WIFSIGNALED(self.forkserver.status())){
            println!("CRASH");
        }
        println!("OK");
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
