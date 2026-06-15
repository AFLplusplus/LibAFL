/// ipt.sys struct definitions, conversion fns and constants
use core::ops::RangeInclusive;

use arbitrary_int::{u3, u4};
use bitbybit::bitfield;
use windows::Win32::Foundation::HANDLE;

pub const TRACE_VERSION: u16 = 1;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct BufferVersion {
    major: u32,
    minor: u32,
}
const BUFFER_VERSION: BufferVersion = BufferVersion { major: 1, minor: 0 };

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConfigureThreadAddressFilterRange {
    thread_handle: HANDLE,
    range_index: u32,
    range_config: FilterRangeSettings,
    start_address: u64,
    end_address: u64,
}

impl ConfigureThreadAddressFilterRange {
    pub const fn new(
        thread_handle: HANDLE,
        range_index: u32,
        filter: &RangeInclusive<u64>,
    ) -> Self {
        Self {
            thread_handle,
            range_index,
            range_config: FilterRangeSettings::Ip,
            start_address: *filter.start(),
            end_address: *filter.end(),
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
#[expect(dead_code, reason = "Not all the config are yet used/supported")]
enum FilterRangeSettings {
    Disable = 0,
    Ip = 1,
    TraceStop = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct GetProcessTrace {
    trace_version: u16,
    _padding: [u8; 6],
    process_handle: u64,
}

impl GetProcessTrace {
    fn new(process_handle: HANDLE) -> Self {
        Self {
            trace_version: TRACE_VERSION,
            _padding: [0u8; 6],
            process_handle: process_handle.0 as u64,
        }
    }
}

#[repr(C)]
pub struct InputBuffer {
    version: BufferVersion,
    input_type: InputType,
    _padding: u32,
    payload: InputPayload,
}

impl InputBuffer {
    const fn new(input_type: InputType, payload: InputPayload) -> Self {
        InputBuffer {
            version: BUFFER_VERSION,
            input_type,
            _padding: 0,
            payload,
        }
    }

    pub fn get_process_trace(process_handle: HANDLE) -> Self {
        Self::new(
            InputType::GetProcessTrace,
            GetProcessTrace::new(process_handle).into(),
        )
    }

    pub fn get_process_trace_size(process_handle: HANDLE) -> Self {
        Self::new(
            InputType::GetProcessTraceSize,
            GetProcessTrace::new(process_handle).into(),
        )
    }

    pub fn pause_thread_trace(thread_handle: HANDLE) -> Self {
        Self::new(
            InputType::PauseThreadTrace,
            PauseResumeThreadTrace::new(thread_handle).into(),
        )
    }

    pub fn resume_thread_trace(thread_handle: HANDLE) -> Self {
        Self::new(
            InputType::ResumeThreadTrace,
            PauseResumeThreadTrace::new(thread_handle).into(),
        )
    }

    pub fn set_thread_ip_filter(
        thread_handle: HANDLE,
        range_index: u32,
        filter: &RangeInclusive<u64>,
    ) -> Self {
        Self::new(
            InputType::ConfigureThreadAddressFilterRange,
            ConfigureThreadAddressFilterRange::new(thread_handle, range_index, filter).into(),
        )
    }

    pub fn start_process_trace(process_handle: HANDLE, options: Options) -> Self {
        Self::new(
            InputType::StartProcessTrace,
            StartProcessTrace {
                process_handle: process_handle.0 as u64,
                options,
            }
            .into(),
        )
    }
}

#[repr(C)]
union InputPayload {
    get_trace: GetProcessTrace,
    start_trace: StartProcessTrace,
    stop_trace: StopProcessTrace,
    configure_thread_address_filter_range: ConfigureThreadAddressFilterRange,
    // query_filter: QueryThreadFilter,
    pause_resume_thread: PauseResumeThreadTrace,
    _pad: [u8; 32],
}

impl From<ConfigureThreadAddressFilterRange> for InputPayload {
    fn from(value: ConfigureThreadAddressFilterRange) -> Self {
        Self {
            configure_thread_address_filter_range: value,
        }
    }
}

impl From<StartProcessTrace> for InputPayload {
    fn from(value: StartProcessTrace) -> Self {
        Self { start_trace: value }
    }
}

impl From<GetProcessTrace> for InputPayload {
    fn from(value: GetProcessTrace) -> Self {
        Self { get_trace: value }
    }
}

impl From<PauseResumeThreadTrace> for InputPayload {
    fn from(value: PauseResumeThreadTrace) -> Self {
        Self {
            pause_resume_thread: value,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
#[expect(dead_code, reason = "Not all the commands are used")]
enum InputType {
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

#[derive(Debug)]
#[repr(u32)]
pub enum Ioctl {
    Request = 0x220004,
    ReadTrace = 0x220006,
}

#[bitfield(u64)]
#[derive(Debug)]
pub struct Options {
    #[bits(0..=3, rw)]
    option_version: u4,
    #[bits(4..=7, rw)]
    timing_settings: u4,
    /// As in `IA32_RTIT_CTL`
    #[bits(8..=11, rw)]
    mtc_frequency: u4,
    #[bits(12..=15, rw)]
    cyc_threshold: u4,
    #[bits(16..=19, rw)]
    topa_pages_pow2: u4,
    /// Not relevant when tracing by process handle
    #[bits(20..=22, rw)]
    match_settings: u3,
    #[bits(23..=23, rw)]
    inherit: bool,
    #[bits(24..=27, rw)]
    mode_settings: u4,
    #[bits(28..=63)]
    reserved: u36,
}

impl Options {
    const VERSION: u4 = u4::new(1);
}

impl Default for Options {
    fn default() -> Self {
        Self::builder()
            .with_option_version(Self::VERSION)
            .with_topa_pages_pow2(u4::new(4)) // 64 kB
            .with_inherit(false)
            .with_mode_settings(u4::new(0)) // todo: better understand IPT_MODE_SETTINGS difference between Ctl and Reg
            .value
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OutGetTraceSize {
    trace_version: u16,
    _padding: [u8; 6],
    pub trace_size: u64,
}

#[repr(C)]
pub union OutputBuffer {
    // get_trace_version: OutGetTraceVersion,
    pub get_trace_size: OutGetTraceSize,
    // query_filter: OutQueryThreadFilter,
    // pause_trace: OutPauseResumeTrace,
    // resume_trace: OutPauseResumeTrace,
    _pad: [u8; 24],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PauseResumeThreadTrace {
    thread_handle: HANDLE,
}

impl PauseResumeThreadTrace {
    const fn new(thread_handle: HANDLE) -> Self {
        PauseResumeThreadTrace { thread_handle }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct StartProcessTrace {
    process_handle: u64,
    options: Options,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct StopProcessTrace {
    process_handle: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct TraceData {
    pub trace_version: u16,
    pub valid_trace: u16,
    pub trace_size: u32,
}

#[repr(C, packed(4))]
#[derive(Debug)]
pub struct TraceHeader {
    pub thread_id: u64,
    timing_settings: u32,
    mtc_frequency: u32,
    frequency_to_tsc_ratio: u32,
    pub ring_buffer_offset: u32,
    pub trace_size: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipt_input_buffer_size() {
        assert_eq!(size_of::<InputBuffer>(), 0x30);
    }
}
