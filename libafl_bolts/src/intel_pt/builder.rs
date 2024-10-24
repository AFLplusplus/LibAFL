use std::{
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        raw::c_void,
    },
    ptr,
    vec::Vec,
};

use arbitrary_int::u4;
use bitbybit::bitfield;
use num_traits::Euclid;
use perf_event_open_sys::{
    bindings::{perf_event_attr, perf_event_mmap_page, PERF_FLAG_FD_CLOEXEC},
    perf_event_open,
};

use super::{IntelPT, NR_ADDR_FILTERS, PAGE_SIZE, PERF_EVENT_TYPE};
use crate::Error;

/// Builder for IntelPT
#[derive(Debug, Clone)]
pub struct IntelPTBuilder {
    pid: Option<i32>,
    cpu: Option<usize>,
    exclude_kernel: bool,
    exclude_hv: bool,
    inherit: bool,
    perf_buffer_size: usize,
    perf_aux_buffer_size: usize,
}

impl Default for IntelPTBuilder {
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
    /// Build the [super::IntelPT] struct
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
            -1 => return Err(Error::last_os_error("Failed to open Intel PT perf event")),
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
