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


const FORKSRV_FD: i32 = 198;
//configure the target. setlimit, setsid, pipe_stdin... , I borrowed the code from Angora fuzzer
//TODO: Better error handling.
pub trait ConfigTarget {
    fn setsid(&mut self) -> &mut Self;
    fn setlimit(&mut self, memlimit: u64) -> &mut Self;
    fn setstdin(&mut self, fd: RawFd, is_stdin: bool) -> &mut Self;
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
            let ret = unsafe {libc::dup2(ctl_pipe.read_end, FORKSRV_FD)};
            if ret < 0 {
                panic!("dup2() failed");
            }
            let ret = unsafe{libc::dup2(st_pipe.write_end, FORKSRV_FD + 1)};
            if ret < 0 {
                panic!("dup2() failed");
            }
            unsafe{
                libc::close(ctl_pipe.read_end);
                libc::close(ctl_pipe.write_end);
                libc::close(st_pipe.read_end);
                libc::close(st_pipe.write_end);
            }
            Ok(())
        };
        unsafe { self.pre_exec(func) }
    }

    fn setstdin(&mut self, fd: RawFd, is_stdin: bool) -> &mut Self {
        if is_stdin {
            let func = move || {
                let ret = unsafe { libc::dup2(fd, libc::STDIN_FILENO) };
                if ret < 0 {
                    panic!("dup2() failed");
                }
                unsafe { libc::close(fd) };
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
    is_stdin: bool,
    status: i32,
}

impl Forkserver {
    pub fn new(target: &'static str, args: Vec<&'static str>, fd: RawFd, memlimit: u64) -> Self {
        //check if we'll use stdin

        let is_stdin = args[0] == "@@";
        let mut status = 0;

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
            .env("__AFL_SHM_ID", "FAKE") //fake, we'll take care of this thing when we have a true observer
            .setlimit(memlimit)
            .setsid()
            .setstdin(fd, is_stdin)
            .setpipe(st_pipe.clone(), ctl_pipe.clone())
            .spawn()
        {
            Ok(_) => (),
            Err(_) => {
                panic!("Command::new() failed");
            }
        };

        //we'll close unneeded endpoints
        unsafe{
            libc::close(ctl_pipe.read_end);
            libc::close(st_pipe.write_end);
        }

        unsafe {
            let rlen = libc::read(st_pipe.read_end, (&mut status) as *mut libc::c_int as *mut libc::c_void, 4);
            if rlen == 4 {
                println!("Forkserver up!");
            }
        };

        Self {
            st_pipe,
            ctl_pipe,
            is_stdin,
            status,
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
}

#[cfg(test)]
mod tests {

    use crate::executors::{Forkserver, OutFile};
    #[test]
    fn test_forkserver() {
        let command = "/home/toka/work/aflsimple/test";
        let args = vec!["@@"];
        let fd = OutFile::new("input_file");
        let forkserver = Forkserver::new(command, args, fd.as_raw_fd(), 0);
    }
}
