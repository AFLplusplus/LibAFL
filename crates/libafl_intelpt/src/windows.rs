#![allow(dead_code)] // todo remove
#![allow(unused_imports)] // todo remove

use alloc::{string::String, vec::Vec};
use core::ptr;
use std::{io, mem::MaybeUninit, ops::RangeInclusive};

use arbitrary_int::{u3, u4, u36};
use bitbybit::bitfield;
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
            Threading::{
                GetCurrentThreadId, GetProcessIdOfThread, OpenProcess, OpenThread,
                PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, THREAD_GET_CONTEXT,
                THREAD_QUERY_LIMITED_INFORMATION,
            },
        },
    },
    core::{HSTRING, w},
};

use crate::utils::current_cpu;

#[repr(u32)]
enum IptIoctl {
    Request = 0x220004,
    ReadTrace = 0x220006,
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

/// Layout (from winipt):
/// - OptionVersion:   bits 0-3   (4 bits) - Must be set to 1
/// - TimingSettings:  bits 4-7   (4 bits) - IPT_TIMING_SETTINGS
/// - MtcFrequency:    bits 8-11  (4 bits) - Bits 14:17 in IA32_RTIT_CTL
/// - CycThreshold:    bits 12-15 (4 bits) - Bits 19:22 in IA32_RTIT_CTL
/// - TopaPagesPow2:   bits 16-19 (4 bits) - Size of buffer as 4KB powers of 2 (4KB->128MB)
/// - MatchSettings:   bits 20-22 (3 bits) - IPT_MATCH_SETTINGS
/// - Inherit:         bit 23     (1 bit)  - Children will be automatically traced
/// - ModeSettings:    bits 24-27 (4 bits) - IPT_MODE_SETTINGS
/// - Reserved:        bits 28-63 (36 bits)
#[bitfield(u64, default = 0)]
#[derive(Debug)]
pub struct IptOptions {
    #[bits(0..=3, rw)]
    pub option_version: u4,
    #[bits(4..=7, rw)]
    pub timing_settings: u4,
    #[bits(8..=11, rw)]
    pub mtc_frequency: u4,
    #[bits(12..=15, rw)]
    pub cyc_threshold: u4,
    #[bits(16..=19, rw)]
    pub topa_pages_pow2: u4,
    /// Not relevant when tracing by process handle
    #[bits(20..=22, rw)]
    pub match_settings: u3,
    #[bits(23..=23, rw)]
    pub inherit: bool,
    #[bits(24..=27, rw)]
    pub mode_settings: u4,
    #[bits(28..=63)]
    reserved: u36,
}
const IPT_OPTION_VERSION: u4 = u4::new(1);
const IPT_TRACE_VERSION: u16 = 1;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StartProcessTrace {
    process_handle: u64,
    options: IptOptions,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GetProcessTrace {
    pub trace_version: u16,
    _padding: [u8; 6],
    pub process_handle: u64,
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
    get_trace: GetProcessTrace,
    start_trace: StartProcessTrace,
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

impl From<StartProcessTrace> for IptInputPayload {
    fn from(value: StartProcessTrace) -> Self {
        Self { start_trace: value }
    }
}

impl From<GetProcessTrace> for IptInputPayload {
    fn from(value: GetProcessTrace) -> Self {
        Self { get_trace: value }
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
#[derive(Debug, Clone, Copy)]
pub struct OutGetTraceSize {
    pub trace_version: u16,
    pub _padding: [u8; 6],
    pub trace_size: u64,
}

#[repr(C)]

union IptOutputBuffer {
    // pub get_trace_version: OutGetTraceVersion,
    pub get_trace_size: OutGetTraceSize,
    // pub query_filter: OutQueryThreadFilter,
    // pub pause_trace: OutPauseResumeTrace,
    // pub resume_trace: OutPauseResumeTrace,
    _pad: [u8; 24],
}

/// Intel Processor Trace (PT)
#[derive(Debug)]
pub struct IntelPT<'a> {
    ipt_handle: PtHandle,
    target_process_handle: PtHandle,
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
            self.send_device_io_request(input)?;
        }
        Ok(())
    }

    pub fn enable_tracing(&mut self) -> windows::core::Result<()> {
        let options = IptOptions::builder()
            .with_inherit(false)
            .with_option_version(IPT_OPTION_VERSION)
            .with_mode_settings(u4::new(0)) // todo: better understand IPT_MODE_SETTINGS difference between Ctl and Reg
            .value;

        let ipt_payload = StartProcessTrace {
            process_handle: self.target_process_handle.inner.0 as u64,
            options,
        };
        let input = IptInputBuffer::new(IptInputType::StartProcessTrace, ipt_payload.into());
        let (_, out_size) = self.send_device_io_request(input)?;
        debug_assert_eq!(out_size, 0);

        Ok(())
    }

    // todo: must not be public, or even exist?
    pub fn get_raw_trace(&mut self) -> windows::core::Result<Vec<u8>> {
        // todo: this looks pretty racy, size might increas ebetween get_trace_size and the actual
        // get trace
        let trace_size = self.get_trace_size()?;
        let mut trace_buffer = Vec::with_capacity(trace_size as usize);

        let ipt_payload = GetProcessTrace {
            trace_version: IPT_TRACE_VERSION,
            _padding: [0u8; 6],
            process_handle: self.target_process_handle.inner.0 as u64,
        };
        let input = IptInputBuffer::new(
            IptInputType::GetProcessTrace,
            IptInputPayload {
                get_trace: ipt_payload.into(),
            },
        );

        let mut out_size = 0;
        unsafe {
            DeviceIoControl(
                self.ipt_handle.inner,
                IptIoctl::ReadTrace as u32,
                Some(&raw const input as *const std::ffi::c_void),
                size_of::<IptInputBuffer>() as u32,
                Some(trace_buffer.as_mut_ptr() as *mut std::ffi::c_void),
                trace_buffer.capacity() as u32,
                Some(&mut out_size),
                None,
            )
        }?;

        assert!((out_size as usize) <= trace_buffer.capacity());
        unsafe{trace_buffer.set_len(out_size as usize);};

        //todo trace_buffer has a header in it

        Ok(trace_buffer)
    }

    fn get_trace_size(&self) -> windows::core::Result<u64> {
        let ipt_payload = GetProcessTrace {
            trace_version: IPT_TRACE_VERSION,
            _padding: [0; 6],
            process_handle: self.target_process_handle.inner.0 as u64,
        };
        let input = IptInputBuffer::new(IptInputType::GetProcessTraceSize, ipt_payload.into());
        let (out, out_size) = self.send_device_io_request(input)?;

        debug_assert_eq!(out_size, size_of::<IptOutputBuffer>() as u32);

        Ok(unsafe { out.get_trace_size.trace_size })
    }

    // pub fn disable_tracing(&mut self) -> windows::core::Result<()> {
    //
    // }

    fn send_device_io_request(
        &self,
        input: IptInputBuffer,
    ) -> windows::core::Result<(IptOutputBuffer, u32)> {
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

        Ok((unsafe { out.assume_init() }, out_size))
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

        let target_thread_handle = unsafe {
            OpenThread(
                THREAD_GET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION,
                false,
                self.target_thread_id,
            )
        }
        .map(|h| PtHandle { inner: h })
        .map_err(|e| {
            libafl_bolts::Error::os_error(e.into(), "Failed to get target thread handle")
        })?;

        let pid = unsafe { GetProcessIdOfThread(target_thread_handle.inner) };

        let target_process_handle =
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
                .map(|h| PtHandle { inner: h })
                .map_err(|e| {
                    libafl_bolts::Error::os_error(e.into(), "Failed to get target process handle")
                })?;

        let ptcov_decoder = PtCoverageDecoderBuilder::new()
            .cpu(current_cpu())
            .images(self.images)
            .build();

        let mut intel_pt = IntelPT {
            ipt_handle,
            target_process_handle,
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
