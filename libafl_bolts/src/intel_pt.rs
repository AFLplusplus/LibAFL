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
        fd::{AsRawFd, FromRawFd, OwnedFd},
        raw::c_void,
    },
    path::Path,
    ptr, slice,
    string::{String, ToString},
    sync::LazyLock,
    vec::Vec,
};

use arbitrary_int::u4;
use bitbybit::bitfield;
use caps::{CapSet, Capability};
use libipt::{
    block::BlockDecoder, AddrConfig, AddrFilter, AddrFilterBuilder, AddrRange, Asid, BlockFlags,
    ConfigBuilder, Cpu, Image, PtError, PtErrorCode,
};
use num_enum::TryFromPrimitive;
use num_traits::Euclid;
use perf_event_open_sys::{
    bindings::{perf_event_attr, perf_event_mmap_page, PERF_FLAG_FD_CLOEXEC},
    ioctls::{DISABLE, ENABLE, SET_FILTER},
    perf_event_open,
};
use raw_cpuid::CpuId;

use crate::{ownedref::OwnedRefMut, Error};

/// Size of a memory page
pub const PAGE_SIZE: usize = 4096;

const PT_EVENT_PATH: &str = "/sys/bus/event_source/devices/intel_pt";

/// Number of address filters available on the running CPU
pub static NR_ADDR_FILTERS: LazyLock<Result<u32, String>> = LazyLock::new(|| {
    // This info is available in two different files, use the second path as fail-over
    let path = format!("{PT_EVENT_PATH}/nr_addr_filters");
    let path2 = format!("{PT_EVENT_PATH}/caps/num_address_ranges");
    let err = format!("Failed to read Intel PT number of address filters from {path} and {path2}");

    let s = fs::read_to_string(&path);
    if let Ok(s) = s {
        let n = s.trim().parse::<u32>();
        if let Ok(n) = n {
            return Ok(n);
        }
    }

    let s2 = fs::read_to_string(&path2).map_err(|_| err.clone())?;
    s2.trim().parse::<u32>().map_err(|_| err)
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

/// Builder for [`IntelPT`]
#[derive(Debug, Clone, PartialEq)]
pub struct IntelPTBuilder {
    pid: Option<i32>,
    cpu: Option<usize>,
    exclude_kernel: bool,
    exclude_hv: bool,
    inherit: bool,
    perf_buffer_size: usize,
    perf_aux_buffer_size: usize,
}

impl From<PtError> for Error {
    fn from(err: PtError) -> Self {
        Self::unknown(format!("libipt error: {err}"))
    }
}

impl IntelPT {
    /// Create a default builder
    ///
    /// Checkout [`IntelPTBuilder::default()`] for more details
    #[must_use]
    pub fn builder() -> IntelPTBuilder {
        IntelPTBuilder::default()
    }

    /// Set filters based on Instruction Pointer (IP)
    ///
    /// Only instructions in `filters` ranges will be traced.
    pub fn set_ip_filters(&mut self, filters: &[RangeInclusive<usize>]) -> Result<(), Error> {
        let str_filter = filters
            .iter()
            .map(|filter| {
                let size = filter.end() - filter.start();
                format!("filter {:#016x}/{:#016x} ", filter.start(), size)
            })
            .reduce(|acc, s| acc + &s)
            .unwrap_or_default();

        // SAFETY: CString::from_vec_unchecked is safe because no null bytes are added to str_filter
        let c_str_filter = unsafe { CString::from_vec_unchecked(str_filter.into_bytes()) };
        match unsafe { SET_FILTER(self.fd.as_raw_fd(), c_str_filter.into_raw()) } {
            -1 => {
                let availability = match Self::availability() {
                    Ok(()) => String::new(),
                    Err(reasons) => format!(" Possible reasons: {reasons}"),
                };
                Err(Error::last_os_error(format!(
                    "Failed to set IP filters.{availability}"
                )))
            }
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

    /// Start tracing
    ///
    /// Be aware that the tracing is not started on [`IntelPT`] construction.
    pub fn enable_tracing(&mut self) -> Result<(), Error> {
        match unsafe { ENABLE(self.fd.as_raw_fd(), 0) } {
            -1 => {
                let availability = match Self::availability() {
                    Ok(()) => String::new(),
                    Err(reasons) => format!(" Possible reasons: {reasons}"),
                };
                Err(Error::last_os_error(format!(
                    "Failed to enable tracing.{availability}"
                )))
            }
            0 => Ok(()),
            ret => Err(Error::unsupported(format!(
                "Failed to enable tracing, ioctl returned unexpected value {ret}"
            ))),
        }
    }

    /// Stop tracing
    ///
    /// This doesn't drop [`IntelPT`], the configuration will be preserved.
    pub fn disable_tracing(&mut self) -> Result<(), Error> {
        match unsafe { DISABLE(self.fd.as_raw_fd(), 0) } {
            -1 => Err(Error::last_os_error("Failed to disable tracing")),
            0 => Ok(()),
            ret => Err(Error::unsupported(format!(
                "Failed to disable tracing, ioctl returned unexpected value {ret}"
            ))),
        }
    }

    /// Decode the traces given the image
    pub fn decode_with_image(&mut self, image: &mut Image) -> Result<Vec<u64>, Error> {
        self.decode(
            None::<fn(_: &mut [u8], _: u64, _: Asid) -> i32>,
            Some(image),
        )
    }

    //         // let read_mem = |buf: &mut [u8], addr: u64| {
    //         //     let src = addr as *const u8;
    //         //     let dst = buf.as_mut_ptr();
    //         //     let size = buf.len();
    //         //     unsafe {
    //         //         ptr::copy_nonoverlapping(src, dst, size);
    //         //     }
    //         // };
    // #[allow(clippy::cast_possible_wrap)]
    // fn decode_with_callback<F: Fn(&mut [u8], u64)>(
    //     &mut self,
    //     read_memory: F,
    //     copy_buffer: Option<&mut Vec<u8>>,
    // ) -> Result<Vec<u64>, Error> {
    //     self.decode(
    //         Some(|buff: &mut [u8], addr: u64, _: Asid| {
    //             debug_assert!(i32::try_from(buff.len()).is_ok());
    //             read_memory(buff, addr);
    //             buff.len() as i32
    //         }),
    //         None,
    //         copy_buffer,
    //     )
    // }

    fn decode<F: Fn(&mut [u8], u64, Asid) -> i32>(
        &mut self,
        read_memory: Option<F>,
        image: Option<&mut Image>,
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
                "The fuzzer run filled the entire PT buffer. Consider increasing the aux buffer \
                size or refining the IP filters."
            );
        }
        let skip = self.previous_decode_head - tail;

        let head_wrap = wrap_aux_pointer(head, self.perf_aux_buffer_size);
        let tail_wrap = wrap_aux_pointer(tail, self.perf_aux_buffer_size);

        smp_rmb();

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

        let mut config = ConfigBuilder::new(data.as_mut())?;
        config.filter(self.ip_filters_to_addr_filter());
        if let Some(cpu) = &*CURRENT_CPU {
            config.cpu(*cpu);
        }
        let flags = BlockFlags::END_ON_CALL.union(BlockFlags::END_ON_JUMP);
        config.flags(flags);
        let mut decoder = BlockDecoder::new(&config.finish())?;
        if let Some(i) = image {
            decoder.set_image(Some(i))?;
        }
        if let Some(rm) = read_memory {
            decoder.image()?.set_callback(Some(rm))?;
        }

        let mut previous_block_ip = 0;
        let mut status;
        'sync: loop {
            match decoder.sync_forward() {
                Ok(s) => {
                    status = s;
                    'block: loop {
                        while status.event_pending() {
                            match decoder.event() {
                                Ok((_, s)) => {
                                    status = s;
                                }
                                Err(e) => {
                                    log::trace!("PT error in event {e:?}");
                                    break 'block;
                                }
                            };
                        }

                        match decoder.next() {
                            Ok((b, s)) => {
                                status = s;
                                let offset = decoder.offset()?;

                                if !b.speculative() && skip < offset {
                                    let id = hash_me(previous_block_ip) ^ hash_me(b.ip());
                                    ips.push(id);
                                    previous_block_ip = b.ip();
                                }
                            }
                            Err((_, e)) => {
                                if e.code() != PtErrorCode::Eos {
                                    log::trace!("PT error in block next {e:?}");
                                }
                            }
                        }
                        if status.eos() {
                            break 'block;
                        }
                    }
                }
                Err(e) => {
                    if e.code() != PtErrorCode::Eos {
                        log::trace!("PT error in sync forward {e:?}");
                    }
                    break 'sync;
                }
            };
        }

        // Advance the trace pointer up to the latest sync point, otherwise next execution's trace
        // might not contain a PSB packet.
        decoder.sync_backward()?;
        let offset = decoder.sync_offset()?;
        unsafe { self.aux_tail.write_volatile(tail + offset) };
        self.previous_decode_head = head;
        Ok(ips)
    }

    /// Check if Intel PT is available on the current system.
    ///
    /// Returns `Ok(())` if Intel PT is available and has the features used by `LibAFL`, otherwise
    /// returns an `Err` containing a description of the reasons.
    ///
    /// If you use this with QEMU check out [`Self::availability_in_qemu()`] instead.
    ///
    /// Due to the numerous factors that can affect `IntelPT` availability, this function was
    /// developed on a best-effort basis.
    /// The outcome of these checks does not fully guarantee whether `IntelPT` will function or not.
    pub fn availability() -> Result<(), String> {
        let mut reasons = Vec::new();
        if cfg!(not(target_os = "linux")) {
            reasons.push("Only linux hosts are supported at the moment".to_owned());
        }
        if cfg!(not(target_arch = "x86_64")) {
            reasons.push("Only x86_64 is supported".to_owned());
        }

        let cpuid = CpuId::new();
        if let Some(vendor) = cpuid.get_vendor_info() {
            if vendor.as_str() != "GenuineIntel" && vendor.as_str() != "GenuineIotel" {
                reasons.push("Only Intel CPUs are supported".to_owned());
            }
        } else {
            reasons.push("Failed to read CPU vendor".to_owned());
        }

        if let Some(ef) = cpuid.get_extended_feature_info() {
            if !ef.has_processor_trace() {
                reasons.push("Intel PT is not supported by the CPU".to_owned());
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
                        reasons.push(format!("Required capability {rc} missing"));
                    }
                }
            }
            Err(e) => reasons.push(format!("Failed to read linux capabilities: {e}")),
        };

        if reasons.is_empty() {
            Ok(())
        } else {
            Err(reasons.join("; "))
        }
    }

    /// Check if Intel PT is available on the current system and can be used in combination with
    /// QEMU.
    ///
    /// If you don't use this with QEMU check out [`IntelPT::availability()`] instead.
    pub fn availability_in_qemu() -> Result<(), String> {
        let mut reasons = match Self::availability() {
            Err(s) => vec![s],
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
            Err(reasons.join("; "))
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

impl Default for IntelPTBuilder {
    /// Create a default builder for [`IntelPT`]
    ///
    /// The default configuration corresponds to:
    /// ```rust
    /// use libafl_bolts::intel_pt::{IntelPTBuilder, PAGE_SIZE};
    /// let builder = unsafe { std::mem::zeroed::<IntelPTBuilder>() }
    ///     .pid(None)
    ///     .cpu(None)
    ///     .exclude_kernel(true)
    ///     .exclude_hv(true)
    ///     .inherit(false)
    ///     .perf_buffer_size(128 * PAGE_SIZE + PAGE_SIZE).unwrap()
    ///     .perf_aux_buffer_size(2 * 1024 * 1024).unwrap();
    /// assert_eq!(builder, IntelPTBuilder::default());
    /// ```
    fn default() -> Self {
        Self {
            pid: None,
            cpu: None,
            exclude_kernel: true,
            exclude_hv: true,
            inherit: false,
            perf_buffer_size: 128 * PAGE_SIZE + PAGE_SIZE,
            perf_aux_buffer_size: 2 * 1024 * 1024,
        }
    }
}

impl IntelPTBuilder {
    /// Build the [`super::IntelPT`] struct
    pub fn build(&self) -> Result<IntelPT, Error> {
        self.check_config();
        let mut perf_event_attr = new_perf_event_attr_intel_pt()?;
        perf_event_attr.set_exclude_kernel(self.exclude_kernel.into());
        perf_event_attr.set_exclude_hv(self.exclude_hv.into());
        perf_event_attr.set_inherit(self.inherit.into());

        let cpu = if let Some(c) = self.cpu {
            i32::try_from(c)?
        } else {
            -1
        };

        // SAFETY: perf_event_attr is properly initialized
        let fd = match unsafe {
            perf_event_open(
                ptr::from_mut(&mut perf_event_attr),
                self.pid.unwrap_or(0),
                cpu,
                -1,
                PERF_FLAG_FD_CLOEXEC.into(),
            )
        } {
            -1 => {
                let availability = match IntelPT::availability() {
                    Ok(()) => String::new(),
                    Err(reasons) => format!(" Possible reasons: {reasons}"),
                };
                return Err(Error::last_os_error(format!(
                    "Failed to open Intel PT perf event.{availability}"
                )));
            }
            fd => {
                // SAFETY: On success, perf_event_open() returns a new file descriptor.
                // On error, -1 is returned, and it is checked above
                unsafe { OwnedFd::from_raw_fd(fd) }
            }
        };

        let perf_buffer = setup_perf_buffer(&fd, self.perf_buffer_size)?;

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
            aux_size.write_volatile(self.perf_aux_buffer_size as u64);
        }

        let perf_aux_buffer = unsafe {
            setup_perf_aux_buffer(&fd, aux_size.read_volatile(), aux_offset.read_volatile())?
        };

        let aux_head = unsafe { ptr::addr_of_mut!((*buff_metadata).aux_head) };
        let aux_tail = unsafe { ptr::addr_of_mut!((*buff_metadata).aux_tail) };

        let ip_filters = Vec::with_capacity(*NR_ADDR_FILTERS.as_ref().unwrap_or(&0) as usize);

        Ok(IntelPT {
            fd,
            perf_buffer,
            perf_aux_buffer,
            perf_buffer_size: self.perf_buffer_size,
            perf_aux_buffer_size: self.perf_aux_buffer_size,
            aux_head,
            aux_tail,
            previous_decode_head: 0,
            ip_filters,
        })
    }

    /// Warn if the configuration is not recommended
    #[inline]
    fn check_config(&self) {
        if self.inherit && self.cpu.is_none() {
            log::warn!(
                "IntelPT set up on all CPUs with process inheritance enabled. This configuration \
                is not recommended and might not work as expected"
            );
        }
    }

    #[must_use]
    /// Set the process to be traced via its `PID`. Set to `None` to trace the current process.
    pub fn pid(mut self, pid: Option<i32>) -> Self {
        self.pid = pid;
        self
    }

    #[must_use]
    /// Set the CPU to be traced, set to `None` to trace all CPUs.
    pub fn cpu(mut self, cpu: Option<usize>) -> Self {
        self.cpu = cpu;
        self
        // TODO change to cpu() and all_cpus()?
    }

    #[must_use]
    /// Do not trace kernel code
    pub fn exclude_kernel(mut self, exclude_kernel: bool) -> Self {
        self.exclude_kernel = exclude_kernel;
        self
    }

    #[must_use]
    /// Do not trace Hypervisor code
    pub fn exclude_hv(mut self, exclude_hv: bool) -> Self {
        self.exclude_hv = exclude_hv;
        self
    }

    #[must_use]
    /// Child processes are traced
    pub fn inherit(mut self, inherit: bool) -> Self {
        self.inherit = inherit;
        self
    }

    /// Set the size of the perf buffer
    pub fn perf_buffer_size(mut self, perf_buffer_size: usize) -> Result<Self, Error> {
        let err = Err(Error::illegal_argument(
            "IntelPT perf_buffer_size should be 1+2^n pages",
        ));
        if perf_buffer_size < PAGE_SIZE {
            return err;
        }
        let (q, r) = (perf_buffer_size - PAGE_SIZE).div_rem_euclid(&PAGE_SIZE);
        if !q.is_power_of_two() || r != 0 {
            return err;
        }

        self.perf_buffer_size = perf_buffer_size;
        Ok(self)
    }

    /// Set the size of the perf aux buffer (actual PT traces buffer)
    pub fn perf_aux_buffer_size(mut self, perf_aux_buffer_size: usize) -> Result<Self, Error> {
        // todo:replace with is_multiple_of once stable
        if perf_aux_buffer_size % PAGE_SIZE != 0 {
            return Err(Error::illegal_argument(
                "IntelPT perf_aux_buffer must be page aligned",
            ));
        }
        if !perf_aux_buffer_size.is_power_of_two() {
            return Err(Error::illegal_argument(
                "IntelPT perf_aux_buffer must be a power of two",
            ));
        }

        self.perf_aux_buffer_size = perf_aux_buffer_size;
        Ok(self)
    }
}

fn new_perf_event_attr_intel_pt() -> Result<perf_event_attr, Error> {
    let type_ = match &*PERF_EVENT_TYPE {
        Ok(t) => Ok(*t),
        Err(e) => Err(Error::unsupported(e.clone())),
    }?;
    let config = PtConfig::builder()
        .with_noretcomp(true)
        .with_psb_period(u4::new(0))
        .build()
        .raw_value;

    let mut attr = perf_event_attr {
        size: size_of::<perf_event_attr>() as u32,
        type_,
        config,
        ..Default::default()
    };

    // Do not enable tracing as soon as the perf_event_open syscall is issued
    attr.set_disabled(true.into());

    Ok(attr)
}

fn setup_perf_buffer(fd: &OwnedFd, perf_buffer_size: usize) -> Result<*mut c_void, Error> {
    match unsafe {
        libc::mmap(
            ptr::null_mut(),
            perf_buffer_size,
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
    match unsafe {
        libc::mmap(
            ptr::null_mut(),
            size as usize,
            // PROT_WRITE sets PT to stop when the buffer is full
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            i64::try_from(offset)?,
        )
    } {
        libc::MAP_FAILED => Err(Error::last_os_error(
            "IntelPT: Failed to mmap perf aux buffer",
        )),
        mmap_addr => Ok(mmap_addr),
    }
}

#[inline]
const fn next_page_aligned_addr(address: u64) -> u64 {
    (address + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1)
}

/// Perf event config for `IntelPT`
///
/// (This is almost mapped to `IA32_RTIT_CTL MSR` by perf)
#[bitfield(u64, default = 0)]
struct PtConfig {
    /// Disable call return address compression. AKA DisRETC in Intel SDM.
    #[bit(11, rw)]
    noretcomp: bool,
    /// Indicates the frequency of PSB packets. AKA PSBFreq in Intel SDM.
    #[bits(24..=27, rw)]
    psb_period: u4,
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
    use std::{arch::asm, process};

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

        let mut ips = pt.decode_with_image(&mut image).unwrap();
        ips.sort_unstable();
        ips.dedup();
        println!("Intel PT traces unique block ips: {ips:#x?}");
    }
}
