//! Intel Processor Trace (PT)  low level code
//!
//! This module interacts with the linux kernel (specifically with perf) and therefore it only works
//! on linux hosts

use std::{
    borrow::ToOwned,
    ffi::CString,
    format, fs,
    ops::RangeInclusive,
    os::{
        fd::{AsRawFd, OwnedFd},
        raw::c_void,
    },
    path::Path,
    slice,
    string::{String, ToString},
    sync::LazyLock,
    vec::Vec,
};

use caps::{CapSet, Capability};
use libipt::{
    block::BlockDecoder, AddrConfig, AddrFilter, AddrFilterBuilder, AddrRange, Asid, BlockFlags,
    ConfigBuilder, Cpu, Image,
};
use num_enum::TryFromPrimitive;
use perf_event_open_sys::ioctls::{DISABLE, ENABLE, SET_FILTER};
use raw_cpuid::CpuId;

use crate::{ownedref::OwnedRefMut, Error};

/// Builder for IntelPT
pub mod builder;
use builder::IntelPTBuilder;

/// Size of a memory page
pub const PAGE_SIZE: usize = 4096;

const PT_EVENT_PATH: &str = "/sys/bus/event_source/devices/intel_pt";

/// Number of address filters available on the running CPU
pub static NR_ADDR_FILTERS: LazyLock<Result<u32, String>> = LazyLock::new(|| {
    let path = format!("{PT_EVENT_PATH}/nr_addr_filters");
    let s = fs::read_to_string(&path)
        .map_err(|_| format!("Failed to read Intel PT number of address filters from {path}"))?;
    s.trim()
        .parse::<u32>()
        .map_err(|_| format!("Failed to parse Intel PT number of address filters in {path}"))
});

static CURRENT_CPU: LazyLock<Option<Cpu>> = LazyLock::new(|| {
    let cpuid = CpuId::new();
    cpuid
        .get_feature_info()
        .map(|fi| Cpu::intel(fi.family_id().into(), fi.model_id(), fi.stepping_id()))
});

static PERF_EVENT_TYPE: LazyLock<Result<u32, String>> = LazyLock::new(|| {
    let path = format!("{PT_EVENT_PATH}/type");
    let s = fs::read_to_string(&path)
        .map_err(|_| format!("Failed to read Intel PT perf event type from {path}"))?;
    s.trim()
        .parse::<u32>()
        .map_err(|_| format!("Failed to parse Intel PT perf event type in {path}"))
});

/// Intel PT mode of operation with KVM
///
/// Check out <https://github.com/torvalds/linux/blob/c2ee9f594da826bea183ed14f2cc029c719bf4da/arch/x86/kvm/vmx/capabilities.h#L373-L381>
/// for more details
#[derive(TryFromPrimitive, Debug)]
#[repr(i32)]
pub enum KvmPTMode {
    /// trace both host/guest and output to host buffer
    System = 0,
    /// trace host and guest simultaneously and output to their respective buffer
    HostGuest = 1,
}

/// Intel Processor Trace (PT)
#[derive(Debug)]
pub struct IntelPT {
    fd: OwnedFd,
    perf_buffer: *mut c_void,
    perf_aux_buffer: *mut c_void,
    perf_buffer_size: usize,
    perf_aux_buffer_size: usize,
    aux_head: *mut u64,
    aux_tail: *mut u64,
    previous_decode_head: u64,
    ip_filters: Vec<RangeInclusive<usize>>,
}

impl IntelPT {
    /// Create a builder
    #[must_use]
    pub fn builder() -> IntelPTBuilder {
        IntelPTBuilder::default()
    }

    /// Set filters based on Instruction Pointer (IP)
    ///
    /// Only instructions in `filters` ranges will be traced.
    pub fn set_ip_filters(&mut self, filters: &[RangeInclusive<usize>]) -> Result<(), Error> {
        let mut str_filter = Vec::with_capacity(filters.len());
        for filter in filters {
            let size = filter.end() - filter.start();
            str_filter.push(format!("filter {:#016x}/{:#016x}", filter.start(), size));
        }

        // SAFETY: CString::from_vec_unchecked is safe because no null bytes are added to str_filter
        let c_str_filter =
            unsafe { CString::from_vec_unchecked(str_filter.join(" ").into_bytes()) };
        match unsafe { SET_FILTER(self.fd.as_raw_fd(), c_str_filter.into_raw()) } {
            -1 => Err(Error::last_os_error("Failed to set IP filters")),
            0 => {
                self.ip_filters = filters.to_vec();
                Ok(())
            }
            ret => Err(Error::unsupported(format!(
                "Failed to set IP filter, ioctl returned unexpected value {ret}"
            ))),
        }
    }

    fn ip_filters_to_addr_filter(&self) -> AddrFilter {
        let mut builder = AddrFilterBuilder::new();
        let mut iter = self
            .ip_filters
            .iter()
            .map(|f| AddrRange::new(*f.start() as u64, *f.end() as u64, AddrConfig::FILTER));
        if let Some(f) = iter.next() {
            builder.addr0(f);
            if let Some(f) = iter.next() {
                builder.addr1(f);
                if let Some(f) = iter.next() {
                    builder.addr2(f);
                    if let Some(f) = iter.next() {
                        builder.addr3(f);
                    }
                }
            }
        }
        builder.finish()
    }

    /// Start the tracing
    ///
    /// Be aware that the tracing is not started on IntelPT construction.
    pub fn enable_tracing(&mut self) -> Result<(), Error> {
        match unsafe { ENABLE(self.fd.as_raw_fd(), 0) } {
            -1 => Err(Error::last_os_error("Failed to enable tracing")),
            0 => Ok(()),
            ret => Err(Error::unsupported(format!(
                "Failed to enable tracing, ioctl returned unexpected value {ret}"
            ))),
        }
    }

    /// Stop Intel PT tracing.
    ///
    /// This doesn't drop IntelPT, the configuration will be preserved.
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
    ) -> Result<Vec<u64>, Error> {
        self.decode(
            None::<fn(_: &mut [u8], _: u64, _: Asid) -> i32>,
            Some(image),
            copy_buffer,
        )
    }

    #[allow(clippy::cast_possible_wrap)]
    pub fn decode_with_callback<F: Fn(&mut [u8], u64)>(
        &mut self,
        read_memory: F,
        copy_buffer: Option<&mut Vec<u8>>,
    ) -> Result<Vec<u64>, Error> {
        self.decode(
            Some(|buff: &mut [u8], addr: u64, _: Asid| {
                debug_assert!(i32::try_from(buff.len()).is_ok());
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
    ) -> Result<Vec<u64>, Error> {
        let mut ips = Vec::new();

        let head = unsafe { self.aux_head.read_volatile() };
        let tail = unsafe { self.aux_tail.read_volatile() };
        if head < tail {
            return Err(Error::unknown(
                "Intel PT: aux buffer head is behind aux tail.",
            ));
        };
        if self.previous_decode_head < tail {
            return Err(Error::unknown(
                "Intel PT: aux previous head is behind aux tail.",
            ));
        };
        let len = (head - tail) as usize;
        if len >= self.perf_aux_buffer_size {
            log::warn!(
                "This fuzzer run resulted in a full PT buffer. Try increasing the aux buffer size or refining the IP filters."
            );
        }
        let skip = self.previous_decode_head - tail;

        let head_wrap = wrap_aux_pointer(head, self.perf_aux_buffer_size);
        let tail_wrap = wrap_aux_pointer(tail, self.perf_aux_buffer_size);

        smp_rmb(); // TODO double check impl

        let mut data = if head_wrap >= tail_wrap {
            unsafe {
                let ptr = self.perf_aux_buffer.add(tail_wrap as usize) as *mut u8;
                OwnedRefMut::Ref(slice::from_raw_parts_mut(ptr, len))
            }
        } else {
            // Head pointer wrapped, the trace is split
            unsafe {
                let first_ptr = self.perf_aux_buffer.add(tail_wrap as usize) as *mut u8;
                let first_len = self.perf_aux_buffer_size - tail_wrap as usize;
                let second_ptr = self.perf_aux_buffer as *mut u8;
                let second_len = head_wrap as usize;
                OwnedRefMut::Owned(
                    [
                        slice::from_raw_parts(first_ptr, first_len),
                        slice::from_raw_parts(second_ptr, second_len),
                    ]
                    .concat()
                    .into_boxed_slice(),
                )
            }
        };

        if let Some(b) = copy_buffer {
            b.extend_from_slice(data.as_ref());
        }

        let mut config =
            ConfigBuilder::new(data.as_mut()).map_err(|e| Error::unknown(e.to_string()))?;
        config.filter(self.ip_filters_to_addr_filter());
        if let Some(cpu) = &*CURRENT_CPU {
            config.cpu(*cpu);
        }
        let flags = BlockFlags::END_ON_CALL.union(BlockFlags::END_ON_JUMP);
        config.flags(flags);
        let mut decoder =
            BlockDecoder::new(&config.finish()).map_err(|e| Error::unknown(e.to_string()))?;
        if let Some(i) = image {
            decoder
                .set_image(Some(i))
                .map_err(|e| Error::unknown(format!("Failed to set image {e}")))?;
        }
        if let Some(rm) = read_memory {
            decoder
                .image()
                .map_err(|e| Error::unknown(e.to_string()))?
                .set_callback(Some(rm))
                .map_err(|e| Error::unknown(format!("Failed to set get memory callback {e}")))?;
        }
        // TODO rewrite decently
        let mut previous_block_ip = 0;
        let mut status;
        loop {
            status = match decoder.sync_forward() {
                Ok(s) => s,
                Err(_) => {
                    // println!("pterror in sync {e:?}");
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
                            println!("pterror in event {e:?}");
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
                    Err(_) => {
                        // libipt-rs library ignores the fact that
                        // Even in case of errors, we may have succeeded in decoding some instructions.
                        // https://github.com/intel/libipt/blob/4a06fdffae39dadef91ae18247add91029ff43c0/ptxed/src/ptxed.c#L1954
                        // Using my fork that fixes this atm
                        // println!("pterror in packet next {e:?}");
                        // println!("err block ip: 0x{:x?}", b.ip());
                        //if skip < decoder.offset().expect("Failed to get decoder offset") {
                        //    ips.push(b.ip());
                        //}
                        // status = Status::from_bits(e.code() as u32).unwrap();
                        break;
                    }
                    Ok((b, s)) => {
                        status = s;

                        // TODO optimize this check and its equivalent up here?
                        if !b.speculative()
                            && skip
                                < decoder
                                    .offset()
                                    .map_err(|e| Error::unknown(e.to_string()))?
                        {
                            let id = hash_me(previous_block_ip) ^ hash_me(b.ip());
                            ips.push(id);
                            previous_block_ip = b.ip();
                        }

                        if status.eos() {
                            break;
                        }
                    }
                }
            }
        }

        // Advance the trace pointer up to the latest sync point, otherwise the next execution might
        // not contain the PSB.
        decoder
            .sync_backward()
            .map_err(|e| Error::unknown(e.to_string()))?;
        let offset = decoder
            .sync_offset()
            .map_err(|e| Error::unknown(e.to_string()))?;
        unsafe { self.aux_tail.write_volatile(tail + offset) };
        self.previous_decode_head = head;
        Ok(ips)
    }

    /// Check if Intel PT is available on the current system.
    ///
    /// This function can be helpful when `IntelPT::try_new` or `set_ip_filter` fail for an unclear
    /// reason.
    ///
    /// Returns `Ok(())` if Intel PT is available and has the features used by `LibAFL`, otherwise
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

        if let Err(e) = &*PERF_EVENT_TYPE {
            reasons.push(e.clone());
        }

        if let Err(e) = &*NR_ADDR_FILTERS {
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

        match caps::read(None, CapSet::Permitted) {
            Ok(current_capabilities) => {
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
            }
            Err(e) => reasons.push(format!("Failed to read linux capabilities: {e}")),
        };

        if reasons.is_empty() {
            Ok(())
        } else {
            Err(Error::unsupported(reasons.join("\n")))
        }
    }

    /// Check if Intel PT is available on the current system and can be used in combination with
    /// QEMU.
    ///
    /// If you don't use this with QEMU check out [`IntelPT::availability()`] instead.
    pub fn availability_in_qemu() -> Result<(), Error> {
        let mut reasons = match Self::availability() {
            Err(Error::Unsupported(s, _)) => vec![s],
            Err(e) => panic!("IntelPT::availability() returned an unknown error {e}"),
            Ok(()) => Vec::new(),
        };

        let kvm_pt_mode_path = "/sys/module/kvm_intel/parameters/pt_mode";
        if let Ok(s) = fs::read_to_string(kvm_pt_mode_path) {
            match s.trim().parse::<i32>().map(TryInto::try_into) {
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
            let ret = libc::munmap(self.perf_aux_buffer, self.perf_aux_buffer_size);
            debug_assert_eq!(ret, 0, "Intel PT: Failed to unmap perf aux buffer");
            let ret = libc::munmap(self.perf_buffer, self.perf_buffer_size);
            debug_assert_eq!(ret, 0, "Intel PT: Failed to unmap perf buffer");
        }
    }
}

// copy pasted from libafl_qemu/src/modules/edges.rs
// adapted from https://xorshift.di.unimi.it/splitmix64.c
#[inline]
#[must_use]
const fn hash_me(mut x: u64) -> u64 {
    x = (x ^ (x.overflowing_shr(30).0))
        .overflowing_mul(0xbf58476d1ce4e5b9)
        .0;
    x = (x ^ (x.overflowing_shr(27).0))
        .overflowing_mul(0x94d049bb133111eb)
        .0;
    x ^ (x.overflowing_shr(31).0)
}

#[inline]
fn smp_rmb() {
    // SAFETY: just a memory barrier
    unsafe {
        core::arch::asm!("lfence", options(nostack, preserves_flags));
    }
}

#[inline]
const fn wrap_aux_pointer(ptr: u64, perf_aux_buffer_size: usize) -> u64 {
    ptr & (perf_aux_buffer_size as u64 - 1)
}

#[cfg(test)]
mod test {
    use std::{arch::asm, fs::OpenOptions, io::Write, process};

    use arbitrary_int::Number;
    use nix::{
        sys::{
            signal::{kill, raise, Signal},
            wait::{waitpid, WaitPidFlag},
        },
        unistd::{fork, ForkResult},
    };
    use proc_maps::get_process_maps;
    use static_assertions::assert_eq_size;

    use super::*;

    // Only 64-bit systems are supported, ensure we can use usize and u64 interchangeably
    assert_eq_size!(usize, u64);

    #[test]
    fn intel_pt_builder_default() {
        let default = IntelPT::builder();
        IntelPT::builder()
            .perf_buffer_size(default.perf_buffer_size)
            .unwrap();
        IntelPT::builder()
            .perf_aux_buffer_size(default.perf_aux_buffer_size)
            .unwrap();
    }

    #[test]
    fn intel_pt_pt_config_noretcomp_format() {
        let ptconfig_noretcomp = PtConfig::DEFAULT.with_noretcomp(true).raw_value;
        let path = format!("{PT_EVENT_PATH}/format/noretcomp");
        let s = fs::read_to_string(&path).expect("Failed to read Intel PT config noretcomp format");
        assert!(
            s.starts_with("config:"),
            "Unexpected Intel PT config noretcomp format"
        );
        let bit = s["config:".len()..]
            .trim()
            .parse::<u32>()
            .expect("Failed to parse Intel PT config noretcomp format");
        assert_eq!(
            ptconfig_noretcomp,
            0b1 << bit,
            "Unexpected Intel PT config noretcomp format"
        );
    }

    #[test]
    fn intel_pt_pt_config_psb_period_format() {
        let ptconfig_psb_period = PtConfig::DEFAULT.with_psb_period(u4::MAX).raw_value;
        let path = format!("{PT_EVENT_PATH}/format/psb_period");
        let s =
            fs::read_to_string(&path).expect("Failed to read Intel PT config psb_period format");
        assert!(
            s.starts_with("config:"),
            "Unexpected Intel PT config psb_period format"
        );
        let from = s["config:".len().."config:".len() + 2]
            .parse::<u32>()
            .expect("Failed to parse Intel PT config psb_period format");
        let to = s["config:".len() + 3..]
            .trim()
            .parse::<u32>()
            .expect("Failed to parse Intel PT config psb_period format");
        let mut format = 0;
        for bit in from..=to {
            format |= 0b1 << bit;
        }
        assert_eq!(
            ptconfig_psb_period, format,
            "Unexpected Intel PT config psb_period format"
        );
    }

    /// To run this test ensure that the executable has the required capabilities.
    /// This can be achieved with the following command:
    /// ```bash
    /// #!/usr/bin/env bash
    ///
    /// # Trigger test compilation
    /// cargo test intel_pt -p libafl --features=intel_pt --no-default-features
    ///
    /// # Find the test binaries
    /// for test_bin in target/debug/deps/libafl*; do
    ///   # Check if the file is a binary
    ///   if file "$test_bin" | grep -q "ELF"; then
    ///     # Set the desired capabilities on the binary
    ///     sudo setcap cap_ipc_lock,cap_sys_ptrace,cap_sys_admin,cap_syslog=ep "$test_bin"
    ///   fi
    /// done
    ///
    /// # Run tests with caps
    /// cargo test intel_pt -p libafl --features=intel_pt --no-default-features -- --show-output
    /// ```
    ///
    /// Or by running with `sudo`:
    /// ```toml
    /// # libafl_qemu/.cargo/config.toml
    /// [target.x86_64-unknown-linux-gnu]
    /// runner = 'sudo -E'
    /// ```
    #[test]
    fn intel_pt_trace_fork() {
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

        let pt_builder = IntelPT::builder().pid(Some(pid.as_raw()));
        let mut pt = pt_builder.build().expect("Failed to create IntelPT");
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
        let mut ips = pt.decode_with_image(&mut image, Some(&mut trace)).unwrap();
        let _ = dump_trace_to_file(&trace)
            .inspect_err(|e| println!("Failed to dump trace to file: {e}"));
        ips.sort_unstable();
        ips.dedup();
        println!("Intel PT traces unique block ips: {ips:#x?}");
    }
    //static mut FILENUM: u32 = 0;
    fn dump_trace_to_file(buff: &[u8]) -> Result<(), Error> {
        let trace_path = "./traces/test_trace_pid_ipt_raw_trace.tmp"; //format!({FILENUM})
                                                                      //unsafe { FILENUM += 1 };
        fs::create_dir_all(Path::new(&trace_path).parent().unwrap())?;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(trace_path)
            .expect("Failed to open trace output file");

        file.write_all(buff)
            .map_err(|e| Error::os_error(e, "Failed to write traces"))?;

        Ok(())
    }
}
