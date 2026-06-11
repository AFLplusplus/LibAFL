mod ipt;

use alloc::{string::String, vec::Vec};
use core::{fmt::Debug, mem::MaybeUninit, ops::RangeInclusive, ptr::slice_from_raw_parts_mut};
#[cfg(feature = "export_raw")]
use std::string::ToString;

use hashbrown::HashMap;
use libafl_bolts::Error;
use ptcov::PtCoverageDecoderBuilder;
pub use ptcov::{CoverageEntry, PtCoverageDecoder, PtImage};
use windows::{
    Win32::{
        Foundation::{HANDLE, INVALID_HANDLE_VALUE},
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
    core::{Owned, w},
};

use crate::utils::current_cpu;

#[derive(Debug)]
struct ThreadCoverageDecoder<'a> {
    decoder: PtCoverageDecoder<'a>,
    previous_decode_head: u32,
}

/// Intel Processor Trace (PT)
#[derive(Debug)]
pub struct IntelPT<'a> {
    ipt_handle: Owned<HANDLE>,
    target_process_handle: Owned<HANDLE>,
    thread_id: Option<u32>,
    ptcov_decoders: HashMap<u64, ThreadCoverageDecoder<'a>>,
    images: &'a [PtImage<'a>],
    last_decode_threads: Vec<u32>,
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

    pub fn set_thread_id(&mut self, thread_id: Option<u32>) {
        self.thread_id = thread_id;
    }

    /// Set filters based on Instruction Pointer (IP)
    ///
    /// Only instructions in `filters` ranges will be traced.
    pub fn set_ip_filters(&mut self, filters: &[RangeInclusive<u64>]) -> windows::core::Result<()> {
        let thread_handle = unsafe {
            Owned::new(if let Some(thread_id) = self.thread_id {
                OpenThread(THREAD_GET_CONTEXT, false, thread_id)?
            } else {
                INVALID_HANDLE_VALUE // TODO apply to all threads?
            })
        };

        for (i, filter) in filters.iter().enumerate() {
            let input =
                ipt::InputBuffer::set_thread_ip_filter(*thread_handle, i.try_into()?, filter);
            let (_, out_size) = self.send_device_io_request(&input)?;
            debug_assert_eq!(out_size, 0);
        }
        Ok(())
    }

    pub fn enable_tracing(&mut self) -> windows::core::Result<()> {
        self.toggle_tracing(true)
    }

    pub fn disable_tracing(&mut self) -> windows::core::Result<()> {
        self.toggle_tracing(false)
    }

    // If the target thread_id is not set, this function will be a best effort based on the threads
    // seen in the last decoding. Enumerating the threads for every iteration kills performances.
    // If a new thread is spawn it is traced by default. If a thread ends, the reativation will fail
    // with a log message but without returning the error.
    fn toggle_tracing(&mut self, enable: bool) -> windows::core::Result<()> {
        if let Some(thread_id) = self.thread_id {
            let mut thread_handle =
                unsafe { Owned::new(OpenThread(THREAD_GET_CONTEXT, false, thread_id)?) };
            self.toggle_thread_tracing(&mut thread_handle, enable)?;
        } else {
            for thread_id in &self.last_decode_threads {
                let mut thread_handle =
                    unsafe { Owned::new(OpenThread(THREAD_GET_CONTEXT, false, *thread_id)?) };
                let _ = self
                    .toggle_thread_tracing(&mut thread_handle, enable)
                    .inspect_err(|e| {
                        log::info!("Failed to toggle tracing for thread {thread_id}: {e}");
                    });
            }
        }

        Ok(())
    }

    fn toggle_thread_tracing(
        &self,
        thread_handle: &mut HANDLE,
        enable: bool,
    ) -> windows::core::Result<()> {
        let input = if enable {
            ipt::InputBuffer::resume_thread_trace(*thread_handle)
        } else {
            ipt::InputBuffer::pause_thread_trace(*thread_handle)
        };
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
        self.last_decode_threads.clear();

        // get trace
        let trace_size = self.get_trace_size()?;
        let mut trace_buffer: Vec<u8> = Vec::with_capacity(trace_size as usize);

        let input = ipt::InputBuffer::get_process_trace(*self.target_process_handle);

        let mut out_size = 0;
        unsafe {
            DeviceIoControl(
                *self.ipt_handle,
                ipt::Ioctl::ReadTrace as u32,
                Some(&raw const input as *const core::ffi::c_void),
                size_of::<ipt::InputBuffer>() as u32,
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

        debug_assert!(trace_buffer.as_ptr().cast::<ipt::TraceData>().is_aligned());
        let trace_data = unsafe {
            trace_buffer
                .as_ptr()
                .cast::<ipt::TraceData>()
                .as_ref_unchecked()
        };
        debug_assert_eq!(trace_data.trace_version, ipt::TRACE_VERSION);
        if trace_data.valid_trace == 0 {
            return Err(Error::runtime(
                "Intel PT: failed to get a valid trace from ipt.sys",
            ));
        }

        let mut slice = &trace_buffer[size_of::<ipt::TraceData>()..];
        while slice.len() >= size_of::<ipt::TraceHeader>() {
            debug_assert!(slice.as_ptr().cast::<ipt::TraceHeader>().is_aligned());
            let inner_header =
                unsafe { slice.as_ptr().cast::<ipt::TraceHeader>().as_ref_unchecked() };
            slice = &slice[size_of::<ipt::TraceHeader>()..];
            self.last_decode_threads.push(inner_header.thread_id as u32);

            if self
                .thread_id
                .is_none_or(|thread_id| u64::from(thread_id) == inner_header.thread_id)
            {
                let ptcov_decoder = self.ptcov_decoders.entry(inner_header.thread_id).or_insert(
                    ThreadCoverageDecoder {
                        decoder: PtCoverageDecoderBuilder::new()
                            .cpu(current_cpu())
                            .images(self.images)
                            .build(),
                        previous_decode_head: 0,
                    },
                );

                let mut split_buffer = Vec::new();
                let trace = if inner_header.ring_buffer_offset >= ptcov_decoder.previous_decode_head
                {
                    &slice[ptcov_decoder.previous_decode_head as usize
                        ..inner_header.ring_buffer_offset as usize]
                } else {
                    split_buffer.extend(
                        &slice[ptcov_decoder.previous_decode_head as usize
                            ..inner_header.trace_size as usize],
                    );
                    split_buffer.extend(&slice[0..inner_header.ring_buffer_offset as usize]);
                    &split_buffer[..]
                };
                ptcov_decoder.previous_decode_head = inner_header.ring_buffer_offset;

                #[cfg(feature = "export_raw")]
                {
                    self.last_decode_trace.extend(slice);
                }

                let coverage = unsafe { &mut *slice_from_raw_parts_mut(map_ptr, map_len) };

                if let Err(e) = ptcov_decoder.decoder.coverage(trace, coverage) {
                    log::warn!("PT trace decoding to coverage failed: {e:?}");
                }
            }
            slice = &slice[inner_header.trace_size as usize..];
        }

        Ok(())
    }

    fn get_trace_size(&self) -> windows::core::Result<u64> {
        let input = ipt::InputBuffer::get_process_trace_size(*self.target_process_handle);
        let (out, out_size) = self.send_device_io_request(&input)?;

        debug_assert_eq!(out_size, size_of::<ipt::OutputBuffer>() as u32);

        Ok(unsafe { out.get_trace_size.trace_size })
    }

    fn send_device_io_request(
        &self,
        input: &ipt::InputBuffer,
    ) -> windows::core::Result<(ipt::OutputBuffer, u32)> {
        let mut out = MaybeUninit::<ipt::OutputBuffer>::uninit();
        let mut out_size = 0;

        unsafe {
            DeviceIoControl(
                *self.ipt_handle,
                ipt::Ioctl::Request as u32,
                Some((&raw const *input).cast()),
                size_of::<ipt::InputBuffer>() as u32,
                Some(out.as_mut_ptr().cast()),
                size_of::<ipt::OutputBuffer>() as u32,
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
}

impl Default for IntelPTBuilder<'_> {
    fn default() -> Self {
        let pid = unsafe { GetCurrentProcessId() };
        Self {
            ip_filters: Vec::new(),
            images: &[],
            pid,
        }
    }
}

impl<'a> IntelPTBuilder<'a> {
    pub fn build(self) -> Result<IntelPT<'a>, Error> {
        // todo: is there a way to start this all set to trace but "paused" as in linux?
        // todo: better error suggesting to start the kernel driver
        let ipt_handle = open_ipt_handle()?;

        let target_process_handle = unsafe {
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, self.pid)
                .map(|h| Owned::new(h))
        }
        .map_err(|e| Error::os_error(e.into(), "Failed to get target process handle"))?;

        let mut intel_pt = IntelPT {
            ipt_handle,
            target_process_handle,
            thread_id: None,
            ptcov_decoders: HashMap::new(),
            images: self.images,
            last_decode_threads: vec![],
            #[cfg(feature = "export_raw")]
            last_decode_trace: Vec::new(),
        };

        let options = ipt::Options::default();

        let input = ipt::InputBuffer::start_process_trace(*intel_pt.target_process_handle, options);
        let (_, out_size) = intel_pt.send_device_io_request(&input)?;
        debug_assert_eq!(out_size, 0);

        // todo: review this, since thread_id could be set later, filter setup can fail or be useless here
        intel_pt
            .set_ip_filters(&self.ip_filters)
            .map_err(|e| Error::os_error(e.into(), "Failed to set IntelPT ip filters"))?;
        Ok(intel_pt)
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

// /// Number of address filters available on the running CPU
// fn nr_addr_filters() -> Result<u8, &'static str> {
//     let cpuid = CpuId::new();
//     cpuid
//         .get_processor_trace_info()
//         .ok_or("Failed to read CPU Processor Trace Info")
//         .map(|pti| pti.configurable_address_ranges())
// }

fn open_ipt_handle() -> windows::core::Result<Owned<HANDLE>> {
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
    .map(|h| unsafe { Owned::new(h) })
}
