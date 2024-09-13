// TODO: This module is not bound to QEMU. Consider moving it somewhere else, it could be used in
// other libafl modules.

use core::{ops::Range, ptr, slice};
use std::{
    ffi::CString,
    fs,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        raw::c_void,
    },
    path::Path,
};

use bitflags::bitflags;
use caps::{CapSet, Capability};
use libafl::Error;
use libipt::{block::BlockDecoder, Asid, ConfigBuilder, Cpu, Image};
use num_enum::TryFromPrimitive;
use object::read::macho::address_to_file_offset;
use perf_event_open_sys::{
    bindings::{perf_event_attr, perf_event_mmap_page, PERF_FLAG_FD_CLOEXEC},
    ioctls::{DISABLE, ENABLE, SET_FILTER},
    perf_event_open,
};
use raw_cpuid::CpuId;

const PAGE_SIZE: usize = 4096;
const PERF_BUFFER_SIZE: usize = (1 + (1 << 7)) * PAGE_SIZE;
const PERF_AUX_BUFFER_SIZE: usize = 64 * 1024 * 1024;
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

// pub trait IntelPTDecoder {
//     fn decode(&mut self, traces: &IntelPTTraces) -> Result((), Error);
// }

// /// Intel official Intel PT trace decoder
// pub struct Libipt {}

// impl IntelPTDecoder for Libipt {
//     fn decode(&mut self, traces: &IntelPTTraces) -> IntelPTTracesResult {
//         todo!()
//     }
// }

// TODO generic decoder: D,
#[derive(Debug)]
pub struct IntelPT {
    fd: OwnedFd,
    perf_buffer: *mut c_void,
    perf_aux_buffer: *mut c_void,
    buff_metadata: *mut perf_event_mmap_page,
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

    pub fn decode_with_image(
        &mut self,
        image: &mut Image,
        copy_buffer: Option<&mut Vec<u8>>,
    ) -> Vec<u64> {
        self.decode(
            None::<fn(_: &mut [u8], _: u64, _: Asid) -> i32>,
            Some(image),
            copy_buffer,
        )
    }

    pub fn decode_with_callback<F: Fn(&mut [u8], u64)>(
        &mut self,
        read_memory: F,
        copy_buffer: Option<&mut Vec<u8>>,
    ) -> Vec<u64> {
        self.decode(
            Some(|buff: &mut [u8], addr: u64, _: Asid| {
                read_memory(buff, addr);
                buff.len() as i32
            }),
            None,
            copy_buffer,
        )
    }

    fn decode<F: Fn(&mut [u8], u64, Asid) -> i32>(
        &mut self,
        read_memory: Option<F>,
        image: Option<&mut Image>,
        copy_buffer: Option<&mut Vec<u8>>,
    ) -> Vec<u64> {
        let mut ips = Vec::new();

        let aux_head = unsafe { ptr::addr_of_mut!((*self.buff_metadata).aux_head) };
        let aux_tail = unsafe { ptr::addr_of_mut!((*self.buff_metadata).aux_tail) };

        let head = wrap_aux_pointer(unsafe { aux_head.read_volatile() });
        let tail = wrap_aux_pointer(unsafe { aux_tail.read_volatile() });
        let data = unsafe { self.perf_aux_buffer.add(tail as usize) } as *mut u8;
        let len = (head - tail) as usize;

        debug_assert!(head >= tail, "Intel PT: aux head is behind aux tail");
        println!("Intel PT: decoding {} bytes", len);
        if let Some(copy_buffer) = copy_buffer {
            copy_buffer.extend_from_slice(unsafe { slice::from_raw_parts(data, len) });
        }

        smp_rmb(); // TODO double check impl

        // TODO handle decoding failures with config.decode.callback = <decode function>; config.decode.context = <decode context>;??
        // apparently the rust library doesn't have the context parameter for the image.set_callback
        // also, under the hood looks like it is passing the callback itself as context to the C fn 🤔
        // TODO remove unwrap()
        let mut config =
            ConfigBuilder::new(unsafe { slice::from_raw_parts_mut(data, len) }).unwrap();
        if let Some(cpu) = current_cpu() {
            config.cpu(cpu);
        }
        let mut decoder = BlockDecoder::new(&config.finish()).unwrap();
        if let Some(i) = image {
            decoder.set_image(Some(i)).expect("Failed to set image");
        }
        if let Some(rm) = read_memory {
            decoder
                .image()
                .unwrap()
                .set_callback(Some(rm))
                .expect("Failed to set get memory callback");
        }
        // TODO rewrite decently
        // TODO consider dropping libipt-rs and using sys, or bindgen ourselves
        let mut status;
        loop {
            status = match decoder.sync_forward() {
                Ok(s) => s,
                Err(e) => {
                    println!("pterror in sync {:?}", e);
                    break;
                }
            };

            loop {
                if loop {
                    if !status.event_pending() {
                        break Ok(());
                    }
                    match decoder.event() {
                        Ok((_, s)) => {
                            // TODO maybe we care about some events?
                            status = s;
                        }
                        Err(e) => {
                            println!("pterror in event {:?}", e);
                            break Err(e);
                        }
                    };
                }
                .is_err()
                {
                    break;
                }

                let block = decoder.next();
                match block {
                    Err((b, e)) => {
                        // libipt-rs library ignores the fact that
                        // Even in case of errors, we may have succeeded in decoding some instructions.
                        // https://github.com/intel/libipt/blob/4a06fdffae39dadef91ae18247add91029ff43c0/ptxed/src/ptxed.c#L1954
                        // Using my fork that fixes this atm
                        println!("pterror in packet next {:?}", e);
                        println!("err block ip: 0x{:x?}", b.ip());
                        ips.push(b.ip());
                        // status = Status::from_bits(e.code() as u32).unwrap();
                        break;
                    }
                    Ok((b, s)) => {
                        status = s;
                        ips.push(b.ip());

                        if status.eos() {
                            break;
                        }
                    }
                }
            }
        }
        ips
    }

    /// Check if Intel PT is available on the current system.
    ///
    /// This function can be helpful when `IntelPT::try_new` or `set_ip_filter` fail for an unclear
    /// reason.
    ///
    /// Returns `Ok(())` if Intel PT is available and has the features used by LibAFL, otherwise
    /// returns an `Err` containing the reasons.
    ///
    /// If you use this with QEMU check out [`Self::availability_in_qemu()`] instead.
    pub fn availability() -> Result<(), Error> {
        let mut reasons = Vec::new();
        if cfg!(not(target_os = "linux")) {
            reasons.push("Only linux hosts are supported at the moment.".to_owned());
        }
        if cfg!(not(target_arch = "x86_64")) {
            reasons.push("Only x86_64 is supported.".to_owned());
        }

        let cpuid = CpuId::new();
        if let Some(vendor) = cpuid.get_vendor_info() {
            if vendor.as_str() != "GenuineIntel" && vendor.as_str() != "GenuineIotel" {
                reasons.push("Only Intel CPUs are supported.".to_owned());
            }
        } else {
            reasons.push("Failed to read CPU vendor".to_owned());
        }

        if let Some(ef) = cpuid.get_extended_feature_info() {
            if !ef.has_processor_trace() {
                reasons.push("Intel PT is not supported by the CPU.".to_owned());
            }
        } else {
            reasons.push("Failed to read CPU Extended Features".to_owned());
        }

        if let Err(e) = intel_pt_perf_type() {
            reasons.push(e.to_string());
        }

        if let Err(e) = intel_pt_nr_addr_filters() {
            reasons.push(e.to_string());
        }

        // official way of knowing if perf_event_open() support is enabled
        // https://man7.org/linux/man-pages/man2/perf_event_open.2.html
        let perf_event_support_path = "/proc/sys/kernel/perf_event_paranoid";
        if !Path::new(perf_event_support_path).exists() {
            reasons.push(format!(
                "perf_event_open() support is not enabled: {perf_event_support_path} not found"
            ));
        }

        // TODO check also the value of perf_event_paranoid, check which values are required by pt
        // https://www.kernel.org/doc/Documentation/sysctl/kernel.txt
        // also, looks like it is distribution dependent
        // https://askubuntu.com/questions/1400874/what-does-perf-paranoia-level-four-do
        // CAP_SYS_ADMIN might make this check useless

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

    /// Check if Intel PT is available on the current system and can be used in combination with
    /// QEMU.
    ///
    /// If you don't use this with QEMU check out [`Self::availability()`] instead.
    pub fn availability_in_qemu() -> Result<(), Error> {
        let mut reasons = match Self::availability() {
            Err(Error::Unsupported(s, _)) => vec![s],
            Err(e) => panic!("IntelPT::availability() returned an unknown error {e}"),
            Ok(()) => Vec::new(),
        };

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
    attr.size = size_of::<perf_event_attr>() as u32;
    attr.type_ = intel_pt_perf_type()?;
    attr.set_disabled(1);
    //TODO parametrize?
    attr.set_exclude_kernel(1);
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

#[inline]
pub fn smp_rmb() {
    unsafe {
        core::arch::asm!("lfence", options(nostack, preserves_flags));
    }
}

#[inline]
pub fn current_cpu() -> Option<Cpu> {
    let cpuid = CpuId::new();
    cpuid
        .get_feature_info()
        .map(|fi| Cpu::intel(fi.family_id() as u16, fi.model_id(), fi.stepping_id()))
}

#[cfg(test)]
mod test {
    use std::{arch::asm, env, fs::OpenOptions, io::Write, process};

    use libc::getpid;
    use nix::{
        sys::{
            signal::{kill, raise, Signal},
            wait::{waitpid, WaitPidFlag},
        },
        unistd::{fork, ForkResult},
    };
    use proc_maps::{get_process_maps, MapRange, Pid};
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
                // This will generate a sequence of tnt packets containing 255 taken branches
                unsafe {
                    let mut count = 0;
                    asm!(
                        "2:",
                        "add {0:r}, 1",
                        "cmp {0:r}, 255",
                        "jle 2b",
                        inout(reg) count,
                        options(nostack)
                    );
                    let _ = count;
                }
                process::exit(0);
            }
            Err(e) => panic!("Fork failed {e}"),
        };

        let mut pt = IntelPT::try_new(pid.as_raw()).expect("Failed to create IntelPT");
        pt.enable_tracing().expect("Failed to enable tracing");

        waitpid(pid, Some(WaitPidFlag::WUNTRACED)).expect("Failed to wait for the child process");
        let maps = get_process_maps(pid.into()).unwrap();
        kill(pid, Signal::SIGCONT).expect("Failed to continue the process");

        waitpid(pid, None).expect("Failed to wait for the child process");
        pt.disable_tracing().expect("Failed to disable tracing");

        let mut image = Image::new(Some("test_trace_pid")).unwrap();
        for map in maps {
            if map.is_exec() && map.filename().is_some() {
                match image.add_file(
                    map.filename().unwrap().to_str().unwrap(),
                    map.offset as u64,
                    map.size() as u64,
                    None,
                    map.start() as u64,
                ) {
                    Err(e) => println!(
                        "Error adding mapping for {:?}: {:?}, skipping",
                        map.filename().unwrap(),
                        e
                    ),
                    Ok(()) => println!(
                        "mapping for {:?} added successfully {:#x} - {:#x}",
                        map.filename().unwrap(),
                        map.start(),
                        map.start() + map.size()
                    ),
                }
            }
        }

        let mut trace = Vec::new();
        let mut ips = pt.decode_with_image(&mut image, Some(&mut trace));
        let _ = dump_trace_to_file(&trace)
            .inspect_err(|e| println!("Failed to dump trace to file: {e}"));
        // remove kernel ips
        ips = ips
            .into_iter()
            .filter(|&addr| addr < 0xff00_0000_0000_0000)
            .collect();
        ips.sort();
        ips.dedup();
        println!("Intel PT traces unique block ips: {:#x?}", ips);
        // TODO: it seems like some userspace traces are not decoded
        // probably because of smth like this in the traces:
        // PSB
        // kernel stuff -> ERROR: not in memory image! sync to next PSB
        // ...                          |
        // userspace skipped stuff      |
        // ...                          |
        // PSB                      <----
        // ...
    }

    fn dump_trace_to_file(buff: &[u8]) -> Result<(), Error> {
        let trace_path = "test_trace_pid_ipt_raw_trace.tmp";
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(trace_path)
            .expect("Failed to open trace output file");

        file.write_all(buff)
            .map_err(|e| Error::os_error(e, "Failed to write traces"))?;

        Ok(())
    }
}
