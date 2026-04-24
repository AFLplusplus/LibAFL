#![allow(dead_code)] // todo remove
#![allow(unused_imports)] // todo remove

use alloc::{string::String, vec::Vec};
use core::ptr;
use std::{io, mem::MaybeUninit, ops::RangeInclusive};

pub use ptcov::PtCoverageDecoder;
use ptcov::{PtCoverageDecoderBuilder, PtImage};
use raw_cpuid::CpuId;
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_NO_BUFFERING, FILE_FLAG_SEQUENTIAL_SCAN,
            FILE_GENERIC_READ, FILE_SHARE_MODE, FILE_SHARE_READ, OPEN_EXISTING,
        },
        System::{
            IO::DeviceIoControl,
            Threading::{GetCurrentThreadId, OpenThread, THREAD_GET_CONTEXT},
        },
    },
    core::{HSTRING, w},
};

use crate::utils::current_cpu;

#[repr(u32)]
enum IptIoctl {
    Request = 0x220004,
}

#[derive(Debug)]
#[repr(u32)]
enum IptInputType {
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

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
enum IptFilterRangeSettings {
    IptFilterRangeDisable = 0,
    IptFilterRangeIp = 1,
    IptFilterRangeTraceStop = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ConfigureThreadAddressFilterRange {
    thread_handle: u64,
    range_index: u32,
    range_config: IptFilterRangeSettings,
    start_address: u64,
    end_address: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct IptBufferVersion {
    major: u32,
    minor: u32,
}
const IPT_BUFFER_VERSION: IptBufferVersion = IptBufferVersion { major: 1, minor: 0 };

#[repr(C)]
union IptInputPayload {
    // get_trace_size: GetProcessTraceSize,
    // get_trace: GetProcessTrace,
    // start_trace: StartProcessTrace,
    // stop_trace: StopProcessTrace,
    configure_thread_address_filter_range: ConfigureThreadAddressFilterRange,
    // query_filter: QueryThreadFilter,
    // pause_resume_thread: PauseResumeThreadTrace,
    _pad: [u8; 32],
}

impl From<ConfigureThreadAddressFilterRange> for IptInputPayload {
    fn from(value: ConfigureThreadAddressFilterRange) -> Self {
        Self {
            configure_thread_address_filter_range: value,
        }
    }
}

#[repr(C)]
struct IptInputBuffer {
    version: IptBufferVersion,
    input_type: IptInputType,
    _padding: u32,
    payload: IptInputPayload,
}

impl IptInputBuffer {
    fn new(input_type: IptInputType, payload: IptInputPayload) -> Self {
        IptInputBuffer {
            version: IPT_BUFFER_VERSION,
            input_type,
            _padding: 0,
            payload,
        }
    }
}

#[repr(C)]
union IptOutputBuffer {
    // pub get_trace_version: OutGetTraceVersion,
    // pub get_trace_size: OutGetTraceSize,
    // pub query_filter: OutQueryThreadFilter,
    // pub pause_trace: OutPauseResumeTrace,
    // pub resume_trace: OutPauseResumeTrace,
    _pad: [u8; 24],
}

/// Intel Processor Trace (PT)
#[derive(Debug)]
pub struct IntelPT<'a> {
    ipt_handle: PtHandle,
    target_thread_handle: PtHandle,
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

    /// Set filters based on Instruction Pointer (IP)
    ///
    /// Only instructions in `filters` ranges will be traced.
    fn set_ip_filters(&mut self, filters: &[RangeInclusive<u64>]) -> windows::core::Result<()> {
        for (i, filter) in filters.iter().enumerate() {
            let ipt_payload = ConfigureThreadAddressFilterRange {
                thread_handle: 0, // todo
                range_index: i.try_into()?,
                range_config: IptFilterRangeSettings::IptFilterRangeIp,
                start_address: *filter.start(),
                end_address: *filter.end(),
            };
            let input = IptInputBuffer::new(
                IptInputType::ConfigureThreadAddressFilterRange,
                ipt_payload.into(),
            );

            let mut out = MaybeUninit::<IptOutputBuffer>::uninit();
            let mut out_size = 0;
            unsafe {
                DeviceIoControl(
                    self.ipt_handle.inner,
                    IptIoctl::Request as u32,
                    Some(&raw const input as *const std::ffi::c_void),
                    size_of::<IptInputBuffer>() as u32,
                    Some(out.as_mut_ptr() as *mut std::ffi::c_void),
                    size_of::<IptOutputBuffer>() as u32,
                    Some(&mut out_size),
                    None,
                )
            }?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct IntelPTBuilder<'a> {
    ip_filters: Vec<RangeInclusive<u64>>,
    images: &'a [PtImage<'a>],
    target_thread_id: u32,
}

impl Default for IntelPTBuilder<'_> {
    fn default() -> Self {
        let target_thread_id = unsafe { GetCurrentThreadId() };
        Self {
            ip_filters: Vec::new(),
            images: &[],
            target_thread_id,
        }
    }
}

impl<'a> IntelPTBuilder<'a> {
    pub fn build(self) -> Result<IntelPT<'a>, libafl_bolts::Error> {
        let ipt_handle = open_ipt_handle()?;

        let target_thread_handle =
            unsafe { OpenThread(THREAD_GET_CONTEXT, false, self.target_thread_id) }
                .map(|h| PtHandle { inner: h })
                .map_err(|e| {
                    libafl_bolts::Error::os_error(e.into(), "Failed to get target thread handle")
                })?;

        let ptcov_decoder = PtCoverageDecoderBuilder::new()
            .cpu(current_cpu())
            .images(self.images)
            .build();

        let mut intel_pt = IntelPT {
            ipt_handle,
            target_thread_handle,
            ptcov_decoder,
        };
        intel_pt.set_ip_filters(&self.ip_filters).map_err(|e| {
            libafl_bolts::Error::os_error(e.into(), "Failed to set IntelPT ip filters")
        })?;
        Ok(intel_pt)
    }

    #[must_use]
    pub fn thread_id(mut self, thread_id: u32) -> Self {
        self.target_thread_id = thread_id;
        self
    }

    #[must_use]
    /// Set filters based on Instruction Pointer (IP)
    pub fn ip_filters(mut self, filters: Vec<RangeInclusive<u64>>) -> Self {
        self.ip_filters = filters;
        self
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
        if let Err(err) = unsafe { CloseHandle(self.inner) } {
            panic!("Failed to close handle: {}", err);
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

fn open_ipt_handle() -> windows::core::Result<PtHandle> {
    let ipt_path = w!("\\??\\IPT\0");

    unsafe {
        CreateFileW(
            ipt_path,
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_NO_BUFFERING,
            None,
        )
    }
    .map(|h| PtHandle { inner: h })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipt_input_buffer_size() {
        assert_eq!(size_of::<IptInputBuffer>(), 0x30);
    }
}
