use std::{
    fs,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        raw::c_void,
    },
};

use bitflags::bitflags;
use libc::ioctl;
use perf_event_open_sys::{
    bindings::{perf_event_attr, perf_event_mmap_page, PERF_FLAG_FD_CLOEXEC},
    perf_event_open,
};

const PAGE_SIZE: usize = 4096;
const PERF_BUFFER_SIZE: usize = ((1 + (1 << 7)) * PAGE_SIZE) as usize;
const PERF_AUX_BUFFER_SIZE: usize = 64 * 1024 * 1024;
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
}

impl IntelPT {
    pub fn new() -> Self {
        // TODO change the unwrap
        let mut perf_event_attr = new_perf_event_attr_intel_pt().unwrap();
        let pid = 0; // TODO pid
        let fd = unsafe {
            OwnedFd::from_raw_fd(perf_event_open(
                &mut perf_event_attr as *mut _,
                pid,
                -1,
                -1,
                PERF_FLAG_FD_CLOEXEC as u64,
            ))
        };
        let perf_buffer = setup_perf_buffer(&fd).unwrap();

        // the first page is a metadata page
        let buff_metadata = &mut unsafe { *perf_buffer.cast::<perf_event_mmap_page>() };
        buff_metadata.aux_offset =
            next_page_aligned_addr((buff_metadata.data_offset + buff_metadata.data_size) as usize)
                as u64;
        buff_metadata.aux_size = PERF_AUX_BUFFER_SIZE as u64;

        let perf_aux_buffer = setup_perf_aux_buffer(&fd, buff_metadata).unwrap();

        Self {
            fd,
            perf_buffer,
            perf_aux_buffer,
        }
    }

    pub fn set_ip_filter(&self) -> Result<(), ()> {
        let filter = "filter 0x7c00/512";
        let ret = unsafe {
            // TODO: clever way of using perf_event.h PERF_EVENT_IOC_SET_FILTER
            // check why bindgen fails
            ioctl(self.fd.as_raw_fd(), 0xdeadbeef, filter.as_ptr())
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(())
        }
        // TODO save ip filters somewhere in the struct
    }
}

#[inline]
const fn next_page_aligned_addr(address: usize) -> usize {
    (address + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
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
    buff_metadata: &perf_event_mmap_page,
) -> Result<*mut c_void, &'static str> {
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
    s.parse::<u32>().map_err(|_| ())
    // TODO better Err()
}
