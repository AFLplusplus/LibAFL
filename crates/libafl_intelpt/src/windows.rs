#![allow(dead_code)] // todo remove
// todo review all the pub

use alloc::{string::String, vec::Vec};
use core::{fmt::Debug, mem::MaybeUninit, ops::RangeInclusive, ptr::slice_from_raw_parts_mut};
#[cfg(feature = "export_raw")]
use std::string::ToString;

use arbitrary_int::{u3, u4};
use bitbybit::bitfield;
use libafl_bolts::Error;
use ptcov::PtCoverageDecoderBuilder;
pub use ptcov::{CoverageEntry, PtCoverageDecoder, PtImage};
use raw_cpuid::CpuId;
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_NO_BUFFERING, FILE_FLAG_SEQUENTIAL_SCAN,
            FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
        },
        System::{
            IO::DeviceIoControl,
            Threading::{
                GetCurrentProcessId, OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION,
                PROCESS_VM_READ, THREAD_GET_CONTEXT,
            },
        },
    },
    core::w,
};

use crate::utils::current_cpu;

#[derive(Debug)]
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
    Disable = 0,
    Ip = 1,
    TraceStop = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ConfigureThreadAddressFilterRange {
    thread_handle: HANDLE,
    range_index: u32,
    range_config: IptFilterRangeSettings,
    start_address: u64,
    end_address: u64,
}

/// Layout (from winipt):
/// - `OptionVersion`:   bits 0-3   (4 bits) - Must be set to 1
/// - `TimingSettings`:  bits 4-7   (4 bits) - `IPT_TIMING_SETTINGS`
/// - `MtcFrequency`:    bits 8-11  (4 bits) - Bits 14:17 in `IA32_RTIT_CTL`
/// - `CycThreshold`:    bits 12-15 (4 bits) - Bits 19:22 in `IA32_RTIT_CTL`
/// - `TopaPagesPow2`:   bits 16-19 (4 bits) - Size of buffer as 4KB powers of 2 (4KB->128MB)
/// - `MatchSettings`:   bits 20-22 (3 bits) - `IPT_MATCH_SETTINGS`
/// - Inherit:         bit 23     (1 bit)  - Children will be automatically traced
/// - `ModeSettings`:    bits 24-27 (4 bits) - `IPT_MODE_SETTINGS`
/// - Reserved:        bits 28-63 (36 bits)
#[bitfield(u64)]
#[derive(Debug)]
struct IptOptions {
    #[bits(0..=3, rw)]
    option_version: u4,
    #[bits(4..=7, rw)]
    timing_settings: u4,
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

impl Default for IptOptions {
    fn default() -> Self {
        Self::builder()
            .with_option_version(Self::VERSION)
            .with_topa_pages_pow2(u4::new(4)) // 64 kB
            .with_inherit(true) // todo: expose this param?
            .with_mode_settings(u4::new(0)) // todo: better understand IPT_MODE_SETTINGS difference between Ctl and Reg
            .value
    }
}

impl IptOptions {
    const VERSION: u4 = u4::new(1);
}

const IPT_TRACE_VERSION: u16 = 1;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct StartProcessTrace {
    process_handle: u64,
    options: IptOptions,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct GetProcessTrace {
    trace_version: u16,
    _padding: [u8; 6],
    process_handle: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PauseResumeThreadTrace {
    thread_handle: HANDLE,
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
    pause_resume_thread: PauseResumeThreadTrace,
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

impl From<PauseResumeThreadTrace> for IptInputPayload {
    fn from(value: PauseResumeThreadTrace) -> Self {
        Self {
            pause_resume_thread: value,
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
#[derive(Debug, Clone, Copy)]
struct OutGetTraceSize {
    trace_version: u16,
    _padding: [u8; 6],
    trace_size: u64,
}

#[repr(C)]
union IptOutputBuffer {
    // pub get_trace_version: OutGetTraceVersion,
    get_trace_size: OutGetTraceSize,
    // pub query_filter: OutQueryThreadFilter,
    // pub pause_trace: OutPauseResumeTrace,
    // pub resume_trace: OutPauseResumeTrace,
    _pad: [u8; 24],
}

#[repr(C)]
#[derive(Debug)]
struct IptTraceData {
    trace_version: u16,
    valid_trace: u16,
    trace_size: u32,
}

#[repr(C, packed(4))]
#[derive(Debug)]
struct IptTraceHeader {
    thread_id: u64,
    timing_settings: u32,
    mtc_frequency: u32,
    frequency_to_tsc_ratio: u32,
    ring_buffer_offset: u32,
    trace_size: u32,
}

/// Intel Processor Trace (PT)
#[derive(Debug)]
pub struct IntelPT<'a> {
    ipt_handle: PtHandle,
    target_process_handle: PtHandle,
    tid: Option<u32>,
    previous_decode_head: u32,
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

    pub fn set_tid(&mut self, tid: Option<u32>) {
        self.tid = tid;
    }

    /// Set filters based on Instruction Pointer (IP)
    ///
    /// Only instructions in `filters` ranges will be traced.
    pub fn set_ip_filters(&mut self, filters: &[RangeInclusive<u64>]) -> windows::core::Result<()> {
        let thread_handle = PtHandle {
            inner: if let Some(tid) = self.tid {
                unsafe { OpenThread(THREAD_GET_CONTEXT, false, tid)? }
            } else {
                INVALID_HANDLE_VALUE // TODO apply to all threads?
            },
        };

        for (i, filter) in filters.iter().enumerate() {
            let ipt_payload = ConfigureThreadAddressFilterRange {
                thread_handle: thread_handle.inner,
                range_index: i.try_into()?,
                range_config: IptFilterRangeSettings::Ip,
                start_address: *filter.start(),
                end_address: *filter.end(),
            };
            let input = IptInputBuffer::new(
                IptInputType::ConfigureThreadAddressFilterRange,
                ipt_payload.into(),
            );
            let (_, out_size) = self.send_device_io_request(&input)?;
            debug_assert_eq!(out_size, 0);
        }
        Ok(())
    }

    pub fn enable_tracing(&mut self) -> windows::core::Result<()> {
        self.toggle_tracing(IptInputType::ResumeThreadTrace)
    }

    pub fn disable_tracing(&mut self) -> windows::core::Result<()> {
        self.toggle_tracing(IptInputType::PauseThreadTrace)
    }

    fn toggle_tracing(&mut self, input_type: IptInputType) -> windows::core::Result<()> {
        let thread_handle = PtHandle {
            inner: if let Some(tid) = self.tid {
                unsafe { OpenThread(THREAD_GET_CONTEXT, false, tid)? }
            } else {
                INVALID_HANDLE_VALUE // TODO apply to all threads?
            },
        };

        let ipt_payload = PauseResumeThreadTrace {
            thread_handle: thread_handle.inner,
        };
        let input = IptInputBuffer::new(
            input_type,
            IptInputPayload {
                pause_resume_thread: ipt_payload,
            },
        );

        // todo: this return the previous state, should we care?
        let (_, out_size) = self.send_device_io_request(&input)?;
        debug_assert_eq!(out_size, 24);

        Ok(())
    }

    /// Fill the coverage map by decoding the PT traces
    ///
    /// This function consumes the traces.
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "Given the structure of the ipt buffer, casts to headers are always aligned"
    )]
    pub fn decode_traces_into_map<T>(
        &mut self,
        // images: &[PtImage], todo: introduce support for JIT/ self modifying code ecc
        map_ptr: *mut T,
        map_len: usize,
    ) -> Result<(), Error>
    where
        T: CoverageEntry,
    {
        // get trace
        let trace_size = self.get_trace_size()?;
        let mut trace_buffer: Vec<u8> = Vec::with_capacity(trace_size as usize);

        let ipt_payload = GetProcessTrace {
            trace_version: IPT_TRACE_VERSION,
            _padding: [0u8; 6],
            process_handle: self.target_process_handle.inner.0 as u64,
        };
        let input = IptInputBuffer::new(
            IptInputType::GetProcessTrace,
            IptInputPayload {
                get_trace: ipt_payload,
            },
        );

        let mut out_size = 0;
        unsafe {
            DeviceIoControl(
                self.ipt_handle.inner,
                IptIoctl::ReadTrace as u32,
                Some(&raw const input as *const core::ffi::c_void),
                size_of::<IptInputBuffer>() as u32,
                Some(trace_buffer.as_mut_ptr() as *mut core::ffi::c_void),
                trace_buffer.capacity() as u32,
                Some(&raw mut out_size),
                None,
            )
        }?;

        debug_assert!((out_size as usize) <= trace_buffer.capacity());
        // SAFETY: Windows driver should not overflow user buffer
        unsafe {
            trace_buffer.set_len(out_size as usize);
        };

        debug_assert!(trace_buffer.as_ptr().cast::<IptTraceData>().is_aligned());
        let trace_data = unsafe {
            trace_buffer
                .as_ptr()
                .cast::<IptTraceData>()
                .as_ref_unchecked()
        };
        assert!(trace_data.valid_trace > 0); // todo better error handling
        assert_eq!(trace_data.trace_version, IPT_TRACE_VERSION);

        let mut slice = &trace_buffer[size_of::<IptTraceData>()..];
        while slice.len() >= size_of::<IptTraceHeader>() {
            debug_assert!(slice.as_ptr().cast::<IptTraceHeader>().is_aligned());
            let inner_header =
                unsafe { slice.as_ptr().cast::<IptTraceHeader>().as_ref_unchecked() };
            slice = &slice[size_of::<IptTraceHeader>()..];
            if self
                .tid
                .is_none_or(|tid| u64::from(tid) == inner_header.thread_id)
            {
                let mut split_buffer = Vec::new();
                let trace = if inner_header.ring_buffer_offset >= self.previous_decode_head {
                    &slice[self.previous_decode_head as usize
                        ..inner_header.ring_buffer_offset as usize]
                } else {
                    split_buffer.extend(
                        &slice
                            [self.previous_decode_head as usize..inner_header.trace_size as usize],
                    );
                    split_buffer.extend(&slice[0..inner_header.ring_buffer_offset as usize]);
                    &split_buffer[..]
                };
                self.previous_decode_head = inner_header.ring_buffer_offset;

                #[cfg(feature = "export_raw")]
                {
                    self.last_decode_trace.extend(slice);
                }

                let coverage = unsafe { &mut *slice_from_raw_parts_mut(map_ptr, map_len) };
                // todo: there should be one decoder for thread?
                if let Err(e) = self.ptcov_decoder.coverage(trace, coverage) {
                    log::warn!("PT trace decoding to coverage failed: {e:?}");
                }
            }
            slice = &slice[inner_header.trace_size as usize..];
        }

        Ok(())
    }

    fn get_trace_size(&self) -> windows::core::Result<u64> {
        let ipt_payload = GetProcessTrace {
            trace_version: IPT_TRACE_VERSION,
            _padding: [0; 6],
            process_handle: self.target_process_handle.inner.0 as u64,
        };
        let input = IptInputBuffer::new(IptInputType::GetProcessTraceSize, ipt_payload.into());
        let (out, out_size) = self.send_device_io_request(&input)?;

        debug_assert_eq!(out_size, size_of::<IptOutputBuffer>() as u32);

        Ok(unsafe { out.get_trace_size.trace_size })
    }

    fn send_device_io_request(
        &self,
        input: &IptInputBuffer,
    ) -> windows::core::Result<(IptOutputBuffer, u32)> {
        let mut out = MaybeUninit::<IptOutputBuffer>::uninit();
        let mut out_size = 0;

        unsafe {
            DeviceIoControl(
                self.ipt_handle.inner,
                IptIoctl::Request as u32,
                Some(&raw const input as *const core::ffi::c_void),
                size_of::<IptInputBuffer>() as u32,
                Some(out.as_mut_ptr() as *mut core::ffi::c_void),
                size_of::<IptOutputBuffer>() as u32,
                Some(&raw mut out_size),
                None,
            )
        }?;

        Ok((unsafe { out.assume_init() }, out_size))
    }

    #[cfg(feature = "export_raw")]
    pub fn dump_last_trace_to_file(&self) -> Result<(), Error> {
        use std::{fs, io::Write, path::Path, time};

        let traces_dir = Path::new("traces");
        fs::create_dir_all(traces_dir)?;
        let timestamp = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .map_err(|e| Error::unknown(e.to_string()))?
            .as_micros();
        let mut file = fs::File::create(traces_dir.join(format!("trace_{timestamp}")))?;
        file.write_all(&self.last_decode_trace)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct IntelPTBuilder<'a> {
    ip_filters: Vec<RangeInclusive<u64>>,
    images: &'a [PtImage<'a>],
    pid: u32,
    tid: Option<u32>,
}

impl Default for IntelPTBuilder<'_> {
    fn default() -> Self {
        let pid = unsafe { GetCurrentProcessId() };
        Self {
            ip_filters: Vec::new(),
            images: &[],
            pid,
            tid: None,
        }
    }
}

impl<'a> IntelPTBuilder<'a> {
    pub fn build(self) -> Result<IntelPT<'a>, Error> {
        // todo: is there a way to start this all set to trace but "paused" as in linux?
        let ipt_handle = open_ipt_handle()?;

        let target_process_handle =
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, self.pid) }
                .map(|h| PtHandle { inner: h })
                .map_err(|e| {
                    Error::os_error(e.into(), "Failed to get target process handle")
                })?;

        let ptcov_decoder = PtCoverageDecoderBuilder::new()
            .cpu(current_cpu())
            .images(self.images)
            .build();

        let mut intel_pt = IntelPT {
            ipt_handle,
            target_process_handle,
            tid: self.tid,
            previous_decode_head: 0,
            ptcov_decoder,
            #[cfg(feature = "export_raw")]
            last_decode_trace: Vec::new(),
        };

        let options = IptOptions::default();

        let ipt_payload = StartProcessTrace {
            process_handle: intel_pt.target_process_handle.inner.0 as u64,
            options,
        };
        let input = IptInputBuffer::new(IptInputType::StartProcessTrace, ipt_payload.into());
        let (_, out_size) = intel_pt.send_device_io_request(&input).unwrap();
        debug_assert_eq!(out_size, 0);

        // todo: review this, since tid could be set later, filter setup can fail or be useless here
        intel_pt
            .set_ip_filters(&self.ip_filters)
            .map_err(|e| Error::os_error(e.into(), "Failed to set IntelPT ip filters"))?;
        Ok(intel_pt)
    }

    #[must_use]
    pub fn thread_id(mut self, thread_id: Option<u32>) -> Self {
        self.tid = thread_id;
        self
    }

    #[must_use]
    pub fn pid(mut self, pid: u32) -> Self {
        self.pid = pid;
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
            panic!("Failed to close handle: {err}");
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
