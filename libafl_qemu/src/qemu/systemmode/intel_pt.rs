// TODO: This module is not bound to QEMU. Consider moving it somewhere else, it could be used in
// other libafl modules.

use core::{ops::Range, ptr, slice};
use std::{
    ffi::CString,
    fs,
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        raw::c_void,
    },
    path::Path,
};

use bitflags::bitflags;
use caps::{CapSet, Capability};
use libafl::Error;
use num_enum::TryFromPrimitive;
use perf_event_open_sys::{
    bindings::{perf_event_attr, perf_event_mmap_page, PERF_FLAG_FD_CLOEXEC},
    ioctls::{DISABLE, ENABLE, SET_FILTER},
    perf_event_open,
};

const PAGE_SIZE: usize = 4096;
const PERF_BUFFER_SIZE: usize = (1 + (1 << 7)) * PAGE_SIZE;
const PERF_AUX_BUFFER_SIZE: usize = 64 * 1024 * 1024;
const CPU_INFO_PATH: &str = "/proc/cpuinfo";
const PT_EVENT_PATH: &str = "/sys/bus/event_source/devices/intel_pt";

#[derive(TryFromPrimitive, Debug)]
#[repr(i32)]
enum KvmPTMode {
    System = 0,
    HostGuest = 1,
}

bitflags! {
    /// IA32_RTIT_CTL MSR flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct PtConfig: u64 {
        /// Disable call return address compression.
        /// AKA DisRETC in Intel SDM
        const NORETCOMP = 0b1 << 11;
    }
}

pub trait IntelPTDecoder {
    fn decode(&mut self, traces) -> TraceResult;
}

#[derive(Debug)]
pub struct IntelPT<D> {
    fd: OwnedFd,
    perf_buffer: *mut c_void,
    perf_aux_buffer: *mut c_void,
    buff_metadata: *mut perf_event_mmap_page,
    decoder: D,
}

impl IntelPT {
    pub fn try_new(pid: i32) -> Result<Self, Error> {
        let mut perf_event_attr = new_perf_event_attr_intel_pt()?;

        let fd = match unsafe {
            perf_event_open(
                &mut perf_event_attr as *mut _,
                pid,
                -1,
                -1,
                PERF_FLAG_FD_CLOEXEC as u64,
            )
        } {
            -1 => return Err(Error::last_os_error("Failed to open Intel PT perf event")),
            fd => {
                // SAFETY: On success, perf_event_open() returns a new file descriptor.
                // On error, -1 is returned, and it is checked above
                unsafe { OwnedFd::from_raw_fd(fd) }
            }
        };

        let perf_buffer = setup_perf_buffer(&fd).unwrap();

        // the first perf_buff page is a metadata page
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

    pub fn set_ip_filters(&mut self, filters: &[Range<usize>]) -> Result<(), Error> {
        let mut str_filter = String::new();
        for filter in filters {
            let size = filter.end - filter.start;
            str_filter.push_str(format!("filter {:#x}/{:#x} ", filter.start, size).as_str());
        }

        debug_assert!(!str_filter.contains("\0"));
        // SAFETY: CString::from_vec_unchecked is safe because no null bytes are present in the
        // string
        let c_str_filter = unsafe { CString::from_vec_unchecked(str_filter.into_bytes()) };
        match unsafe { SET_FILTER(self.fd.as_raw_fd(), c_str_filter.into_raw()) } {
            -1 => Err(Error::last_os_error("Failed to set IP filters")),
            0 => Ok(()),
            ret => Err(Error::unsupported(format!(
                "Failed to set IP filter, ioctl returned unexpected value {ret}"
            ))),
        }
    }

    pub fn enable_tracing(&mut self) -> Result<(), Error> {
        match unsafe { ENABLE(self.fd.as_raw_fd(), 0) } {
            -1 => Err(Error::last_os_error("Failed to enable tracing")),
            0 => Ok(()),
            ret => Err(Error::unsupported(format!(
                "Failed to enable tracing, ioctl returned unexpected value {ret}"
            ))),
        }
    }

    pub fn disable_tracing(&mut self) -> Result<(), Error> {
        match unsafe { DISABLE(self.fd.as_raw_fd(), 0) } {
            -1 => Err(Error::last_os_error("Failed to disable tracing")),
            0 => Ok(()),
            ret => Err(Error::unsupported(format!(
                "Failed to disable tracing, ioctl returned unexpected value {ret}"
            ))),
        }
    }

    pub fn read_trace_into<T: Write>(&self, buff: &mut T) -> Result<(), Error> {
        // TODO: should we read also the normal buffer?
        let aux_head = unsafe { ptr::addr_of_mut!((*self.buff_metadata).aux_head) };
        let aux_tail = unsafe { ptr::addr_of_mut!((*self.buff_metadata).aux_tail) };

        let head = wrap_aux_pointer(unsafe { aux_head.read_volatile() });
        let tail = wrap_aux_pointer(unsafe { aux_tail.read_volatile() });

        debug_assert!(head >= tail, "Intel PT: aux head is behind aux tail");

        // smp_rmb(); // TODO check how to call this in Rust

        buff.write_all(unsafe {
            slice::from_raw_parts(
                self.perf_aux_buffer.add(tail as usize) as *const _,
                (head - tail) as usize,
            )
        })
        .map_err(|e| Error::os_error(e, "Failed to write traces"))?;

        unsafe { aux_tail.write_volatile(tail) }
        Ok(())
    }

    /// Check if Intel PT is available on the current system.
    ///
    /// This function can be helpful when `IntelPT::try_new` or `set_ip_filter` fail for an unclear
    /// reason.
    ///
    /// Returns `Ok(())` if Intel PT is available with all the features used by LibAFL, otherwise
    /// returns an `Err` containing the reasons.
    pub fn availability() -> Result<(), Error> {
        let mut reasons = Vec::new();
        if cfg!(not(target_os = "linux")) {
            reasons.push("Only linux hosts are supported at the moment.".to_owned());
        }
        if cfg!(not(target_arch = "x86_64")) {
            reasons.push("Only x86_64 is supported.".to_owned());
        }

        if let Ok(cpu_info) = fs::read_to_string(CPU_INFO_PATH) {
            if !cpu_info.contains("GenuineIntel") && !cpu_info.contains("GenuineIotel") {
                reasons.push("Only Intel CPUs are supported.".to_owned());
            }
            if !cpu_info.contains("intel_pt") {
                reasons.push("Intel PT is not supported by the CPU.".to_owned());
            }
        } else {
            reasons.push("Failed to read CPU info".to_owned());
        }

        if let Err(e) = intel_pt_perf_type() {
            reasons.push(e.to_string());
        }

        if let Err(e) = intel_pt_nr_addr_filters() {
            reasons.push(e.to_string());
        }

        // official way of knowing if perf_event_open() support is enabled
        // https://man7.org/linux/man-pages/man2/perf_event_open.2.html
        let perf_event_support_path: &str = "/proc/sys/kernel/perf_event_paranoid";
        if !Path::new(perf_event_support_path).exists() {
            reasons.push(format!(
                "perf_event_open() support is not enabled: {perf_event_support_path} not found"
            ));
        }

        let kvm_pt_mode_path = "/sys/module/kvm_intel/parameters/pt_mode";
        if let Ok(s) = fs::read_to_string(kvm_pt_mode_path) {
            match s.trim().parse::<i32>().map(|i| i.try_into()) {
                Ok(Ok(KvmPTMode::System)) => (),
                Ok(Ok(KvmPTMode::HostGuest)) => reasons.push(format!(
                    "KVM Intel PT mode must be set to {:?} `{}` to be used with libafl_qemu",
                    KvmPTMode::System,
                    KvmPTMode::System as i32
                )),
                _ => reasons.push(format!(
                    "Failed to parse KVM Intel PT mode in {kvm_pt_mode_path}"
                )),
            }
        };

        if let Ok(current_capabilities) = caps::read(None, CapSet::Permitted) {
            let required_caps = [
                Capability::CAP_IPC_LOCK,
                Capability::CAP_SYS_PTRACE,
                Capability::CAP_SYS_ADMIN, // TODO: CAP_PERFMON doesn't look to be enough!?
                Capability::CAP_SYSLOG,
            ];

            for rc in required_caps {
                if !current_capabilities.contains(&rc) {
                    reasons.push(format!("Required capability {rc} missing."));
                }
            }
        } else {
            reasons.push("Failed to read linux capabilities".to_owned());
        }

        if reasons.is_empty() {
            Ok(())
        } else {
            Err(Error::unsupported(reasons.join("\n")))
        }
    }
}

impl Drop for IntelPT {
    fn drop(&mut self) {
        unsafe {
            let ret = libc::munmap(self.perf_aux_buffer, PERF_AUX_BUFFER_SIZE);
            debug_assert_eq!(ret, 0, "Intel PT: Failed to unmap perf aux buffer");
            let ret = libc::munmap(self.perf_buffer, PERF_BUFFER_SIZE);
            debug_assert_eq!(ret, 0, "Intel PT: Failed to unmap perf buffer");
        }
    }
}

#[inline]
const fn next_page_aligned_addr(address: u64) -> u64 {
    (address + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1)
}

fn setup_perf_buffer(fd: &OwnedFd) -> Result<*mut c_void, Error> {
    match unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            PERF_BUFFER_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            0,
        )
    } {
        libc::MAP_FAILED => Err(Error::last_os_error("IntelPT: Failed to mmap perf buffer")),
        mmap_addr => Ok(mmap_addr),
    }
}

fn setup_perf_aux_buffer(fd: &OwnedFd, size: u64, offset: u64) -> Result<*mut c_void, Error> {
    // PROT_WRITE sets PT to stop when the buffer is full
    match unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            offset as i64,
        )
    } {
        libc::MAP_FAILED => Err(Error::last_os_error(
            "IntelPT: Failed to mmap perf aux buffer",
        )),
        mmap_addr => Ok(mmap_addr),
    }
}

fn new_perf_event_attr_intel_pt() -> Result<perf_event_attr, Error> {
    let mut attr: perf_event_attr = unsafe { core::mem::zeroed() };
    attr.size = core::mem::size_of::<perf_event_attr>() as u32;
    attr.type_ = intel_pt_perf_type()?;
    attr.set_disabled(1);
    attr.config |= PtConfig::NORETCOMP.bits();

    Ok(attr)
}

fn intel_pt_perf_type() -> Result<u32, Error> {
    let path = format!("{PT_EVENT_PATH}/type");
    let s = fs::read_to_string(&path).map_err(|e| {
        Error::os_error(
            e,
            format!("Failed to read Intel PT perf event type from {path}"),
        )
    })?;
    s.trim().parse::<u32>().map_err(|_| {
        Error::unsupported(format!(
            "Failed to parse Intel PT perf event type in {path}"
        ))
    })
}

fn intel_pt_nr_addr_filters() -> Result<u32, Error> {
    let path = format!("{PT_EVENT_PATH}/nr_addr_filters");
    let s = fs::read_to_string(&path).map_err(|e| {
        Error::os_error(
            e,
            format!("Failed to read Intel PT number of address filters from {path}"),
        )
    })?;
    s.trim().parse::<u32>().map_err(|_| {
        Error::unsupported(format!(
            "Failed to parse Intel PT number of address filters in {path}"
        ))
    })
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
        unistd::{fork, ForkResult},
    };
    use static_assertions::{assert_eq_size, const_assert_eq};

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
        if let Err(reason) = IntelPT::availability() {
            // Mark as `skipped` once this will be possible https://github.com/rust-lang/rust/issues/68007
            println!("Intel PT is not available, skipping test. Reasons:");
            println!("{reason}");
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
