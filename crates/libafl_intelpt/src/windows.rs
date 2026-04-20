#![allow(dead_code)] // todo remove
#![allow(unused_imports)] // todo remove

use alloc::vec::Vec;
use core::ptr;
use std::{io, prelude::rust_2015::String};
use std::ops::RangeInclusive;
pub use ptcov::PtCoverageDecoder;
use ptcov::{PtCoverageDecoderBuilder, PtImage};
use raw_cpuid::CpuId;
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_NO_BUFFERING, FILE_FLAG_SEQUENTIAL_SCAN,
        FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
    },
};
use libafl_bolts::Error;
use crate::utils::current_cpu;

#[derive(Debug)]
#[repr(u32)]
pub enum IptInputType {
    GetTraceVersion = 0,
    GetProcessTraceSize,
    GetProcessTrace,
    StartCoreTracing,
    RegisterExtendedImageForTracing,
    StartProcessTrace,
    StopProcessTrace,
    PauseThreadTrace,
    ResumeThreadTrace,
    QueryProcessTrace,
    QueryCoreTrace,
    StopTraceOnEachCore = 12,
    ConfigureThreadAddressFilterRange,
    QueryThreadAddressFilterRange,
    QueryThreadTraceStopRangeEntered,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ConfigureThreadAddressFilterRange {
    thread_handle: u64,
    range_index: u32,
    range_config: u32,
    start_address: u64,
    end_address: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct IptBufferVersion {
    buffer_major_version: u32,
    buffer_minor_version: u32,
}

#[repr(C)]
union IptInputUnion {
    // get_trace_size: GetProcessTraceSize,
    // get_trace: GetProcessTrace,
    // start_trace: StartProcessTrace,
    // stop_trace: StopProcessTrace,
    configure_thread_address_filter_range: ConfigureThreadAddressFilterRange,
    // query_filter: QueryThreadFilter,
    // pause_resume_thread: PauseResumeThreadTrace,
    _pad: [u8; 32],
}

#[repr(C)]
pub struct IptInputBuffer {
    version: IptBufferVersion,
    input_type: IptInputType,
    _padding: u32,
    u: IptInputUnion,
}

/// Intel Processor Trace (PT)
#[derive(Debug)]
pub struct IntelPT<'a> {
    ipt_handle: PtHandle,

    // previous_decode_head: u64,
    ptcov_decoder: PtCoverageDecoder<'a>,
    #[cfg(feature = "export_raw")]
    last_decode_trace: Vec<u8>,
}

impl<'a> IntelPT<'a> {
    /// Create a default builder
    ///
    /// Checkout [`IntelPTBuilder::default()`] for more details
    #[must_use]
    pub fn builder() -> IntelPTBuilder<'a> {
        IntelPTBuilder::default()
    }

    // /// Set filters based on Instruction Pointer (IP)
    // ///
    // /// Only instructions in `filters` ranges will be traced.
    // fn set_ip_filters(&mut self, filters: &[RangeInclusive<u64>]) -> Result<(), Error> {
    //     Ok(())
    // }
}

#[derive(Debug, Default)]
pub struct IntelPTBuilder<'a> {
    images: &'a [PtImage<'a>],
}

impl<'a> IntelPTBuilder<'a> {
    pub fn build(self) -> io::Result<IntelPT<'a>> {
        let ipt_handle = open_ipt_handle()?;

        let ptcov_decoder = PtCoverageDecoderBuilder::new()
            .cpu(current_cpu())
            .images(self.images)
            .build();

        Ok(IntelPT {
            ipt_handle,
            ptcov_decoder,
        })
    }

    #[must_use]
    pub fn images(mut self, images: &'a [PtImage<'_>]) -> Self {
        self.images = images;
        self
    }
}

#[derive(Debug)]
struct PtHandle {
    inner: HANDLE,
}

impl Drop for PtHandle {
    fn drop(&mut self) {
        if unsafe { CloseHandle(self.inner) } == 0 {
            let err = io::Error::last_os_error();
            panic!("Failed to close ipt handle: {}", err);
        }
    }
}

pub(crate) fn availability_in_windows() -> Result<(), String> {
    let mut reasons = Vec::new();

    if let Err(e) = open_ipt_handle() {
        let err = format!(
            "Failed to open IPT device: {e}; \n\
            Make sure the ipt service is running with `sc start ipt` from an admin shell."
        );
        reasons.push(err);
    }

    if reasons.is_empty() {
        Ok(())
    } else {
        Err(reasons.join("; "))
    }
}

/// Number of address filters available on the running CPU
fn nr_addr_filters() -> Result<u8, &'static str> {
    let cpuid = CpuId::new();
    cpuid
        .get_processor_trace_info()
        .ok_or("Failed to read CPU Processor Trace Info")
        .map(|pti| pti.configurable_address_ranges())
}

fn open_ipt_handle() -> io::Result<PtHandle> {
    let ipt_path: Vec<u16> = "\\??\\IPT\0".encode_utf16().collect();

    let handle = unsafe {
        CreateFileW(
            ipt_path.as_ptr(),
            FILE_GENERIC_READ,
            FILE_SHARE_READ,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_NO_BUFFERING,
            ptr::null_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        let err = io::Error::last_os_error();
        return Err(err);
    }

    Ok(PtHandle { inner: handle })
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn ipt_input_buffer_size() {
        assert_eq!(size_of::<IptInputBuffer>(), 0x30);
    }
}
