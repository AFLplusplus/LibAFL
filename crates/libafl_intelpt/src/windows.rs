//! Intel Processor Trace code using the `ipt.sys` Windows driver.
//!
//! This code is heavily inspired by `winipt` by Alex Ionescu and its other authors.
//! Credits also go to Frederic Kah and Justin Avril, who drafted the initial implementation.

// todo: Cross-platform API divergence
//
// lib.rs glob-re-exports both modules, so IntelPT/IntelPTBuilder are the "same" type by name but not by API: pid(u32) vs pid(Option<i32>), set_thread_id + pub set_ip_filters (Windows) vs builder .ip_filters() and private set_ip_filters (Linux), no PtCoverageDecoderBuilder or last_decode_trace() re-export on Windows, IntelPTBuilder derives Clone + PartialEq only on Linux. The example fuzzer already pays for this with #[cfg(windows)] and #[cfg_attr(not(windows), expect(unused_mut))]. Converging pid() and moving thread_id/ip_filters onto the builder would also make the "must set thread_id before filters" ordering unrepresentable rather than a runtime Error::unsupported.

use alloc::{string::String, vec::Vec};
use core::{fmt::Debug, ops::RangeInclusive, ptr::slice_from_raw_parts_mut};
#[cfg(feature = "export_raw")]
use std::string::ToString;

use ::ipt::{AddressFilterMode, Ipt, TraceBuffer};
use libafl_bolts::Error;
use ptcov::PtCoverageDecoderBuilder;
pub use ptcov::{CoverageEntry, PtCoverageDecoder, PtImage};
use raw_cpuid::CpuId;
use windows::{
    Win32::{
        Foundation::HANDLE,
        System::Threading::{
            GetCurrentProcessId, GetCurrentThreadId, OpenProcess, OpenThread,
            PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, THREAD_GET_CONTEXT,
        },
    },
    core::Owned,
};

use crate::utils::current_cpu;

/// Intel Processor Trace (PT)
#[derive(Debug)]
pub struct IntelPT<'a> {
    ipt: Ipt,
    target_process_handle: Owned<HANDLE>,
    thread_id: u32,
    decoder: PtCoverageDecoder<'a>,
    previous_decode_head: u32,
    #[cfg(feature = "export_raw")]
    last_decode_trace: Vec<u8>,
}

impl<'a> IntelPT<'a> {
    /// Create a default builder tracing the current process. You **must add images** to have a
    /// working decoder.
    #[must_use]
    pub fn builder() -> IntelPTBuilder<'a> {
        IntelPTBuilder::default()
    }

    /// Set filters based on Instruction Pointer (IP)
    ///
    /// Only instructions in `filters` ranges will be traced.
    // todo set_ip_filters leaves stale ranges armed — windows.rs:80-95. It only programs 0..filters.len(); ranges from a previous call keep filtering. Linux replaces the entire filter string, so behavior diverges. Also i.try_into().unwrap() panics instead of erroring, and there's no upfront filters.len() <= nr_addr_filters() check — that only surfaces as a warning after the ioctl already failed.
    pub fn set_ip_filters(&mut self, filters: &[RangeInclusive<u64>]) -> Result<(), Error> {
        let thread_handle =
            unsafe { Owned::new(OpenThread(THREAD_GET_CONTEXT, false, self.thread_id)?) };

        for (i, filter) in filters.iter().enumerate() {
            self.ipt
                .configure_thread_address_filter_range(
                    *thread_handle,
                    i.try_into().unwrap(),
                    AddressFilterMode::Filter,
                    *filter.start(),
                    *filter.end(),
                )
                .inspect_err(|_| {
                    log::warn!(
                        "Available IP filters on the CPU: {}",
                        nr_addr_filters().unwrap_or(0)
                    );
                })?;
        }
        log::debug!("PT filtering for IP in {filters:x?}");
        Ok(())
    }

    /// Resume tracing of the traced thread
    pub fn enable_tracing(&mut self) -> Result<(), Error> {
        let thread_handle =
            unsafe { Owned::new(OpenThread(THREAD_GET_CONTEXT, false, self.thread_id)?) };
        self.ipt.resume_thread_trace(*thread_handle)?;
        Ok(())
    }

    /// Pause tracing of the traced thread
    ///
    /// This doesn't drop [`IntelPT`], the configuration will be preserved.
    pub fn disable_tracing(&mut self) -> Result<(), Error> {
        let thread_handle =
            unsafe { Owned::new(OpenThread(THREAD_GET_CONTEXT, false, self.thread_id)?) };
        self.ipt.pause_thread_trace(*thread_handle)?;
        Ok(())
    }

    /// Fill the coverage map by decoding the PT traces
    ///
    /// This function consumes the traces.
    pub fn decode_traces_into_map<T>(
        &mut self,
        // images: &[PtImage], todo: introduce support for JIT/ self modifying code ecc
        map_ptr: *mut T,
        map_len: usize,
    ) -> Result<(), Error>
    where
        T: CoverageEntry,
    {
        #[cfg(feature = "export_raw")]
        {
            self.last_decode_trace.clear();
        }

        //todo TOCTOU on the trace buffer size — windows.rs:164-169. A thread created between get_trace_buffer_size and get_trace_buffer makes the buffer too small; per the ipt docs that's STATUS_BUFFER_OVERFLOW/STATUS_BUFFER_TOO_SMALL. Worth one retry.
        // get trace
        let trace_size = self
            .ipt
            .get_trace_buffer_size(*self.target_process_handle)?;
        // todo - TraceBuffer::with_capacity(trace_size) allocates a fresh ~1 MiB × n_threads buffer on every post_exec, and split_buffer allocates per record. Both should live in IntelPT and be reused/grown. Linux is zero-copy off the mmap here, so the Windows path is meaningfully more expensive.
        let mut trace_buffer = TraceBuffer::with_capacity(trace_size);
        self.ipt
            .get_trace_buffer(*self.target_process_handle, &mut trace_buffer)?;

        for (header, data) in &trace_buffer {
            if u64::from(self.thread_id) == header.thread_id {
                log::trace!("PT previous_decode_head: {}", self.previous_decode_head);
                let mut split_buffer = Vec::new();
                // Both offsets index the thread's trace buffer, whose size is fixed when tracing
                // starts, hence they can never be out of `data`'s bounds.
                let trace = if header.output_offset >= self.previous_decode_head {
                    &data[self.previous_decode_head as usize..header.output_offset as usize]
                } else {
                    log::trace!("PT ring buffer wrapped, handling split trace");
                    split_buffer.extend(&data[self.previous_decode_head as usize..]);
                    split_buffer.extend(&data[0..header.output_offset as usize]);
                    &split_buffer
                };
                self.previous_decode_head = header.output_offset;

                #[cfg(feature = "export_raw")]
                {
                    self.last_decode_trace.extend(trace);
                }

                let coverage = unsafe { &mut *slice_from_raw_parts_mut(map_ptr, map_len) };

                if let Err(e) = self.decoder.coverage(trace, coverage) {
                    log::warn!("PT trace decoding to coverage failed: {e:x?}");
                    coverage.fill(0.into());
                }
            }
        }

        Ok(())
    }

    /// Dump the raw trace used in the last decoding to the file
    /// `./traces/trace_<unix epoch in micros>`
    #[cfg(feature = "export_raw")]
    pub fn dump_last_trace_to_file(&self) -> Result<(), Error> {
        use std::{fs, io::Write, path::Path, time};

        let traces_dir = Path::new("traces");
        fs::create_dir_all(traces_dir)?;
        let timestamp = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .map_err(|e| Error::unknown(e.to_string()))?
            .as_micros();
        let file_path = traces_dir.join(format!("trace_{timestamp}"));
        let mut file = fs::File::create(&file_path)?;
        file.write_all(&self.last_decode_trace)?;

        log::trace!("Last decoded PT trace saved to {}", file_path.display());
        Ok(())
    }
}

/// Builder for [`IntelPT`]
#[derive(Debug)]
pub struct IntelPTBuilder<'a> {
    images: &'a [PtImage<'a>],
    ipt: Option<(Ipt, Owned<HANDLE>)>,
    pid: u32,
    tid: u32,
}

impl Default for IntelPTBuilder<'_> {
    /// Trace the calling thread of the current process, with no images and no tracing started
    fn default() -> Self {
        let pid = unsafe { GetCurrentProcessId() };
        let tid = unsafe { GetCurrentThreadId() };
        Self {
            images: &[],
            ipt: None,
            pid,
            tid,
        }
    }
}

impl<'a> IntelPTBuilder<'a> {
    /// Build the [`IntelPT`] struct, starting tracing if [`IntelPTBuilder::start_tracing`] was not
    /// called yet
    pub fn build(mut self) -> Result<IntelPT<'a>, Error> {
        let decoder = PtCoverageDecoderBuilder::new()
            .cpu(current_cpu())
            .images(self.images)
            .build();

        // todo: Double check if is possible to start tracing as "paused", as we need to start
        // tracing in order to set IP filters, but this can lead to trace pollution.
        if self.ipt.is_none() {
            self = self.start_tracing()?;
        }
        let (ipt, target_process_handle) = self.ipt.take().unwrap();

        // todo - OpenThread + CloseHandle on every enable_tracing/disable_tracing — two handle round-trips per execution. Cache the Owned<HANDLE>.
        let intel_pt = IntelPT {
            ipt,
            target_process_handle,
            thread_id: self.tid,
            decoder,
            previous_decode_head: 0,
            #[cfg(feature = "export_raw")]
            last_decode_trace: Vec::new(),
        };

        Ok(intel_pt)
    }

    /// # Panics
    /// Panics if tracing already started
    #[must_use]
    pub fn pid(mut self, pid: u32) -> Self {
        assert!(
            self.ipt.is_none(),
            "Tracing already started, set the PID before starting tracing!"
        );
        self.pid = pid;
        self
    }

    /// Set the executable memory used to decode the traces
    #[must_use]
    pub fn images(mut self, images: &'a [PtImage<'_>]) -> Self {
        self.images = images;
        self
    }

    /// Start tracing the target process
    ///
    /// Call this before creating the traced thread to avoid losing its first traces, otherwise
    /// [`IntelPTBuilder::build`] takes care of it. Returns an error if tracing is already started.
    pub fn start_tracing(mut self) -> Result<Self, Error> {
        if self.ipt.is_some() {
            return Err(Error::illegal_state("Tracing already started"));
        }

        // todo: - build() doesn't enrich failures with availability() the way Linux does, so an Ipt::open() failure surfaces as a bare windows::core::Error. (The ipt crate's own log feature is on by default and logs the sc start ipt hint, so this is mitigated but inconsistent.)
        let ipt = Ipt::open()?;
        let target_process_handle = unsafe {
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, self.pid)
                .map(|h| Owned::new(h))
        }?;
        let options = ipt::IptOption::default();
        ipt.start_process_trace(*target_process_handle, options)?;

        self.ipt = Some((ipt, target_process_handle));
        Ok(self)
    }

    /// Set the thread to be traced via its `TID`. Defaults to the thread creating the builder.
    #[must_use]
    pub fn thread_id(mut self, tid: u32) -> Self {
        self.tid = tid;
        self
    }
}

pub(crate) fn availability_in_windows() -> Result<(), String> {
    let mut reasons = Vec::new();

    if let Err(e) = Ipt::open() {
        reasons.push(format!(
            "Failed to open IPT device: {e}; \n\
            Make sure the ipt service is running with `sc start ipt` from an admin shell."
        ));
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
        .inspect(|nr_filters| log::trace!("PT number of available IP filters: {nr_filters:?}"))
}
