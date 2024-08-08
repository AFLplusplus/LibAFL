use core::slice;
use std::{
    fs,
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        raw::c_void,
    },
    ptr,
};

use bitflags::bitflags;
use caps::{CapSet, Capability};
use perf_event_open_sys::{
    bindings::{perf_event_attr, perf_event_mmap_page, PERF_FLAG_FD_CLOEXEC},
    ioctls::{DISABLE, ENABLE, SET_FILTER},
    perf_event_open,
};

const PAGE_SIZE: usize = 4096;
const PERF_BUFFER_SIZE: usize = (1 + (1 << 7)) * PAGE_SIZE;
const PERF_AUX_BUFFER_SIZE: usize = 64 * 1024 * 1024;
const CPU_INFO_PATH: &str = "/proc/cpuinfo";
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

// TODO use libaflerr instead of () for Result

#[derive(Debug)]
pub struct IntelPT {
    fd: OwnedFd,
    perf_buffer: *mut c_void,
    perf_aux_buffer: *mut c_void,
    buff_metadata: *mut perf_event_mmap_page,
}

impl IntelPT {
    pub fn try_new(pid: i32) -> Result<Self, ()> {
        let mut perf_event_attr = new_perf_event_attr_intel_pt()?;

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
        let buff_metadata = perf_buffer.cast::<perf_event_mmap_page>();
        let aux_offset = unsafe { ptr::addr_of_mut!((*buff_metadata).aux_offset) };
        let aux_size = unsafe { ptr::addr_of_mut!((*buff_metadata).aux_size) };
        let data_offset = unsafe { ptr::addr_of_mut!((*buff_metadata).data_offset) };
        let data_size = unsafe { ptr::addr_of_mut!((*buff_metadata).data_size) };

        unsafe {
            aux_offset.write_volatile(next_page_aligned_addr(
                data_offset.read_volatile() + data_size.read_volatile(),
            ));
            aux_size.write_volatile(PERF_AUX_BUFFER_SIZE as u64);
        }

        let perf_aux_buffer = unsafe {
            setup_perf_aux_buffer(&fd, aux_size.read_volatile(), aux_offset.read_volatile())
                .unwrap()
        };

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

    pub fn read_trace_into<T: Write>(&self, buff: &mut T) -> Result<(), ()> {
        let aux_head = unsafe { ptr::addr_of_mut!((*self.buff_metadata).aux_head) };
        let aux_tail = unsafe { ptr::addr_of_mut!((*self.buff_metadata).aux_tail) };

        let head = wrap_aux_pointer(unsafe { aux_head.read_volatile() });
        let tail = wrap_aux_pointer(unsafe { aux_tail.read_volatile() });

        // TODO if head < tail

        // smp_rmb(); // TODO check how to call this in Rust

        buff.write_all(unsafe {
            slice::from_raw_parts(
                self.perf_aux_buffer.add(tail as usize) as *const _,
                (head - tail) as usize,
            )
        })
        .map_err(|_| ())?;

        unsafe { aux_tail.write_volatile(tail) }
        Ok(())
    }

    /// Check if Intel PT is available on the current system.
    ///
    /// This function can be helpful when `IntelPT::try_new()` fails for an unclear reason.
    ///
    /// Returns `Ok(())` if Intel PT is available, otherwise an `Err` with the reasons.
    pub fn availability() -> Result<(), Vec<&'static str>> {
        let mut reasons = Vec::new();
        if cfg!(not(target_os = "linux")) {
            reasons.push("Only linux hosts are supported at the moment.");
        }
        if cfg!(not(target_arch = "x86_64")) {
            reasons.push("Only x86_64 is supported.");
        }

        if let Ok(cpu_info) = fs::read_to_string(CPU_INFO_PATH) {
            if !cpu_info.contains("GenuineIntel") && !cpu_info.contains("GenuineIotel") {
                reasons.push("Only Intel CPUs are supported.");
            }
            if !cpu_info.contains("intel_pt") {
                reasons.push("Intel PT is not supported by the CPU.");
            }
        } else {
            reasons.push("Failed to read CPU info");
        }

        if let Ok(current_capabilities) = caps::read(None, CapSet::Permitted) {
            let required_caps = [
                Capability::CAP_IPC_LOCK,
                Capability::CAP_SYS_PTRACE,
                Capability::CAP_SYS_ADMIN,
                Capability::CAP_SYSLOG,
            ];

            let is_missing = required_caps
                .map(|rc| current_capabilities.contains(&rc))
                .iter()
                .any(|c| !c);
            if is_missing {
                reasons.push(
                    "Required capability missing. \
                    Required caps are cap_ipc_lock, cap_sys_ptrace, cap_sys_admin, cap_syslog.",
                );
            }
        } else {
            reasons.push("Failed to read linux capabilities");
        }

        if reasons.is_empty() {
            Ok(())
        } else {
            Err(reasons)
        }
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
    size: u64,
    offset: u64,
) -> Result<*mut c_void, &'static str> {
    // PROT_WRITE sets PT to stop when the buffer is full
    let mmap_addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            offset as i64,
        )
    };
    if mmap_addr == libc::MAP_FAILED {
        // println!("Err: {}", std::io::Error::last_os_error().to_string());
        Err("IntelPT: Failed to mmap perf aux buffer")
    } else {
        Ok(mmap_addr)
    }
}

fn new_perf_event_attr_intel_pt() -> Result<perf_event_attr, ()> {
    let mut attr: perf_event_attr = unsafe { core::mem::zeroed() };
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
    use std::{fs::OpenOptions, process};

    use nix::{
        sys::{
            signal::{kill, raise, Signal},
            wait::{waitpid, WaitPidFlag},
        },
        unistd::{fork, ForkResult, Pid},
    };

    use super::*;

    // PERF_BUFFER_SIZE should be 1+2^n pages
    const_assert_eq!(
        (PERF_BUFFER_SIZE - PAGE_SIZE) & (PERF_BUFFER_SIZE - PAGE_SIZE - 1),
        0
    );
    // PERF_AUX_BUFFER_SIZE must be page aligned
    const_assert_eq!(PERF_AUX_BUFFER_SIZE % PAGE_SIZE, 0);
    // PERF_AUX_BUFFER_SIZE must be a power of two
    const_assert_eq!(PERF_AUX_BUFFER_SIZE & (PERF_AUX_BUFFER_SIZE - 1), 0);
    // Only 64-bit systems are supported, ensure we can use usize and u64 interchangeably
    assert_eq_size!(usize, u64);

    /// To run this test ensure that the executable has the required capabilities.
    /// This can be achieved with the following command:
    /// ```bash
    /// #!/bin/bash
    ///
    /// # Find the test binaries
    /// for test_bin in target/debug/deps/libafl_qemu*; do
    ///   # Check if the file is a binary
    ///   if file "$test_bin" | grep -q "ELF"; then
    ///     # Set the desired capabilities on the binary
    ///     sudo setcap cap_ipc_lock,cap_sys_ptrace,cap_sys_admin,cap_syslog=ep "$test_bin"
    ///   fi
    /// done
    /// ```
    /// Or by running with `sudo`:
    /// ```toml
    /// # libafl_qemu/.cargo/config.toml
    /// [target.x86_64-unknown-linux-gnu]
    /// runner = 'sudo -E'
    /// ```
    #[test]
    fn trace_pid() {
        if let Err(reasons) = IntelPT::availability() {
            // Mark as `skipped` once this will be possible https://github.com/rust-lang/rust/issues/68007
            println!("Intel PT is not available, skipping test. Reasons:");
            for reason in reasons {
                println!("\t- {}", reason);
            }
            return;
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
            Err(e) => panic!("Fork failed {e}"),
        };

        let mut pt = IntelPT::try_new(pid.as_raw()).expect("Failed to create IntelPT");
        pt.enable_tracing().expect("Failed to enable tracing");

        waitpid(pid, Some(WaitPidFlag::WUNTRACED)).expect("Failed to wait for the child process");
        kill(pid, Signal::SIGCONT).expect("Failed to continue the process");

        let trace_path = "test_trace_pid_ipt_raw_trace.tmp";
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(trace_path)
            .expect("Failed to open trace output file");

        waitpid(pid, None).expect("Failed to wait for the child process");

        pt.disable_tracing().expect("Failed to disable tracing");
        pt.read_trace_into(&mut file)
            .expect("Failed to write traces");
        fs::remove_file(trace_path).expect("Failed to remove trace file");
    }
}
