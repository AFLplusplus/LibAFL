use core::slice;
use std::{
    fs,
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        raw::c_void,
    },
};

use bitflags::bitflags;
use perf_event_open_sys::{
    bindings::{perf_event_attr, perf_event_mmap_page, PERF_FLAG_FD_CLOEXEC},
    ioctls::{DISABLE, ENABLE, SET_FILTER},
    perf_event_open,
};

const PAGE_SIZE: usize = 4096;
const PERF_BUFFER_SIZE: usize = ((1 + (1 << 1)) * PAGE_SIZE) as usize;
const PERF_AUX_BUFFER_SIZE: usize = 64 * 1024;
const PT_EVENT_TYPE_PATH: &str = "/sys/bus/event_source/devices/intel_pt/type";

bitflags! {
    /// IA32_RTIT_CTL MSR flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct PtConfig: u64 {
        /// Disable call return address compression.
        /// AKA DisRETC in Intel SDM
        const NORETCOMP = 0b1 << 11;
    }
}

// TODO consider moving to static assert crate
const _: () = assert!(
    ((PERF_BUFFER_SIZE - PAGE_SIZE) & (PERF_BUFFER_SIZE - PAGE_SIZE - 1)) == 0,
    "PERF_BUFFER_SIZE should be 1+2^n pages"
);
const _: () = assert!(
    (PERF_AUX_BUFFER_SIZE % PAGE_SIZE) == 0,
    "PERF_AUX_BUFFER_SIZE must be page aligned"
);
const _: () = assert!(
    (PERF_AUX_BUFFER_SIZE & (PERF_AUX_BUFFER_SIZE - 1)) == 0,
    "PERF_AUX_BUFFER_SIZE must be a power of two"
);
// Ensure we can use usize and u64 interchangeably
const _: () = assert!(
    size_of::<usize>() == size_of::<u64>(),
    "IntelPT: Only 64-bit systems are supported"
);

// TODO use libaflerr instead of () for Result

pub struct IntelPT {
    fd: OwnedFd,
    // TODO use proper types
    perf_buffer: *mut c_void,
    perf_aux_buffer: *mut c_void,
    buff_metadata: perf_event_mmap_page,
}

impl IntelPT {
    pub fn try_new(pid: i32) -> Result<Self, ()> {
        // TODO change the unwrap
        let mut perf_event_attr = new_perf_event_attr_intel_pt().unwrap();

        let perf_event_open_ret = unsafe {
            perf_event_open(
                &mut perf_event_attr as *mut _,
                pid,
                -1,
                -1,
                PERF_FLAG_FD_CLOEXEC as u64,
            )
        };
        if perf_event_open_ret == -1 {
            return Err(());
        }
        // SAFETY: On success, perf_event_open() returns a new file descriptor.
        // On error, -1 is returned, and is checked above
        let fd = unsafe { OwnedFd::from_raw_fd(perf_event_open_ret) };
        let perf_buffer = setup_perf_buffer(&fd).unwrap();

        // the first page is a metadata page
        let mut buff_metadata = unsafe { *perf_buffer.cast::<perf_event_mmap_page>() };
        buff_metadata.aux_offset =
            next_page_aligned_addr(buff_metadata.data_offset + buff_metadata.data_size);
        buff_metadata.aux_size = PERF_AUX_BUFFER_SIZE as u64;

        let perf_aux_buffer = setup_perf_aux_buffer(&fd, &buff_metadata).unwrap();

        Ok(Self {
            fd,
            perf_buffer,
            perf_aux_buffer,
            buff_metadata,
        })
    }

    pub fn set_ip_filter(&mut self) -> Result<(), ()> {
        let filter = c"filter 0x7c00/512".to_owned(); //TODO use a param
        let ret = unsafe { SET_FILTER(self.fd.as_raw_fd(), filter.into_raw()) };

        if ret == 0 {
            Ok(())
        } else {
            Err(())
        }
        // TODO save ip filters somewhere in the struct
    }

    pub fn enable_tracing(&mut self) -> Result<(), ()> {
        let ret = unsafe { ENABLE(self.fd.as_raw_fd(), 0) };

        if ret == 0 {
            Ok(())
        } else {
            Err(())
        }
        // TODO save tracing state or maybe better to check with the kernel?
    }

    pub fn disable_tracing(&mut self) -> Result<(), ()> {
        let ret = unsafe { DISABLE(self.fd.as_raw_fd(), 0) };

        if ret == 0 {
            Ok(())
        } else {
            Err(())
        }
        // TODO save tracing state or maybe better to check with the kernel?
    }

    pub fn read_trace_into<T: Write>(&self, buff: &mut T) {
        let head = wrap_aux_pointer(self.buff_metadata.aux_head);
        let tail = wrap_aux_pointer(self.buff_metadata.aux_tail);
        // smp_rmb(); // TODO check how to call this in Rust

        // fwrite(perf_aux_buf + tail, 1, head - tail, f);
        buff.write_all(unsafe {
            slice::from_raw_parts(
                self.perf_aux_buffer.add(tail as usize) as *const _,
                (head - tail) as usize,
            )
        })
        .unwrap();

        // pc->aux_tail = head;
    }
}

impl Drop for IntelPT {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.perf_buffer, PERF_BUFFER_SIZE);
            libc::munmap(self.perf_aux_buffer, PERF_AUX_BUFFER_SIZE);
        }
    }
}

#[inline]
const fn next_page_aligned_addr(address: u64) -> u64 {
    (address + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1)
}

fn setup_perf_buffer(fd: &OwnedFd) -> Result<*mut c_void, &'static str> {
    println!("fd: {:?}", fd);
    let mmap_addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            PERF_BUFFER_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            0,
        )
    };
    if mmap_addr == libc::MAP_FAILED {
        Err("IntelPT: Failed to mmap perf buffer")
    } else {
        Ok(mmap_addr)
    }
}

fn setup_perf_aux_buffer(
    fd: &OwnedFd,
    buff_metadata: &perf_event_mmap_page,
) -> Result<*mut c_void, &'static str> {
    println!(
        "aux_offset: {}, aux_size: {}, fd: {:?}",
        buff_metadata.aux_offset as i64, buff_metadata.aux_size as usize, fd
    );
    // PROT_WRITE sets PT to stop when the buffer is full
    let mmap_addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            buff_metadata.aux_size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            buff_metadata.aux_offset as i64,
        )
    };
    if mmap_addr == libc::MAP_FAILED {
        println!("Err: {}", std::io::Error::last_os_error().to_string());
        Err("IntelPT: Failed to mmap perf aux buffer")
    } else {
        Ok(mmap_addr)
    }
}

pub fn new_perf_event_attr_intel_pt() -> Result<perf_event_attr, ()> {
    let mut attr: perf_event_attr;
    unsafe {
        attr = core::mem::zeroed();
    }
    attr.size = core::mem::size_of::<perf_event_attr>() as u32;
    attr.type_ = intel_pt_perf_type()?;
    attr.set_disabled(1);
    attr.config |= PtConfig::NORETCOMP.bits();

    Ok(attr)
}

fn intel_pt_perf_type() -> Result<u32, ()> {
    let s = fs::read_to_string(PT_EVENT_TYPE_PATH).map_err(|_| ())?;
    s.trim().parse::<u32>().map_err(|_| ())
    // TODO better Err()
}

#[inline]
const fn wrap_aux_pointer(ptr: u64) -> u64 {
    ptr & (PERF_AUX_BUFFER_SIZE as u64 - 1)
}

#[cfg(test)]
mod test {
    use core::panic;
    use std::{
        fs::OpenOptions, io, os::unix::process::CommandExt, process, process::Command,
        thread::sleep, time::Duration,
    };

    use caps::{CapSet, Capability};
    use nix::{
        sys::{
            signal::{kill, raise, Signal},
            wait::{waitpid, WaitPidFlag},
        },
        unistd::{fork, pause, write, ForkResult, Pid},
    };

    use super::*;

    #[test]
    fn trace_pid() {
        let current_capabilities =
            caps::read(None, CapSet::Permitted).expect("Failed to read linux capabilities");
        // TODO enforce this outside tests somewhere?
        let required_caps = [
            Capability::CAP_IPC_LOCK,
            Capability::CAP_SYS_PTRACE,
            Capability::CAP_SYS_ADMIN,
            Capability::CAP_SYSLOG,
        ];

        for rc in &required_caps {
            if !current_capabilities.contains(rc) {
                println!("Required capability {:?} is missing, skipping test.", rc);
                // Mark as `skipped` once this will be possible https://github.com/rust-lang/rust/issues/68007
                return;
            }
        }

        let pid = match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => child,
            Ok(ForkResult::Child) => {
                raise(Signal::SIGSTOP).expect("Failed to stop the process");
                let mut dummy = false;
                for _ in 0..1000 {
                    dummy = !dummy;
                }
                process::exit(0);
            }
            Err(_) => panic!("Fork failed"),
        };

        // brakes at aux mmap, EINVAL... maybe should add some barriers to let the kenrnel know
        // about the new metadata? why don't I have this problem in C?
        let mut pt = IntelPT::try_new(pid.as_raw()).expect("Failed to create IntelPT");

        waitpid(pid, Some(WaitPidFlag::WUNTRACED)).expect("Failed to wait for the child process");
        kill(pid, Signal::SIGCONT).expect("Failed to continue the process");

        waitpid(pid, None).expect("Failed to wait for the child process");
    }

    struct LoggerToFile {
        file: std::fs::File,
    }

    impl LoggerToFile {
        fn new() -> Self {
            let file = OpenOptions::new()
                .append(true)
                .create(true)
                .open("ipt_raw_trace")
                .expect("Unable to open trace output file");
            Self { file }
        }

        fn log(&mut self, msg: &str) {
            use std::io::Write;
            self.file.write_all(msg.as_bytes()).unwrap();
        }
    }
}
