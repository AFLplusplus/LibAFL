/// Intel Processor Trace code using the `ipt.sys` Windows driver.
///
/// This code is heavily inspired by `winipt` by Alex Ionescu and its other authors.
/// Credits also go to Frederic Kah and Justin Avril, who drafted the initial implementation.
use alloc::{string::String, vec::Vec};
use core::{fmt::Debug, ops::RangeInclusive, ptr::slice_from_raw_parts_mut};
#[cfg(feature = "export_raw")]
use std::string::ToString;

use ::ipt::{AddressFilterMode, Ipt, TraceBuffer};
use hashbrown::HashMap;
use libafl_bolts::Error;
use ptcov::PtCoverageDecoderBuilder;
pub use ptcov::{CoverageEntry, PtCoverageDecoder, PtImage};
use raw_cpuid::CpuId;
use windows::{
    Win32::{
        Foundation::HANDLE,
        System::Threading::{
            GetCurrentProcessId, OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION,
            PROCESS_VM_READ, THREAD_GET_CONTEXT,
        },
    },
    core::Owned,
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
    ipt: Ipt,
    target_process_handle: Owned<HANDLE>,
    thread_id: Option<u32>,
    ptcov_decoders: HashMap<u64, ThreadCoverageDecoder<'a>>,
    images: &'a [PtImage<'a>],
    last_decode_threads: Vec<u32>,
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

    pub fn set_thread_id(&mut self, thread_id: Option<u32>) {
        if let Some(thread_id) = thread_id {
            log::debug!("PT filtering for thread {thread_id}");
        } else {
            log::debug!("PT filtering for thread disabled");
        }

        self.thread_id = thread_id;
    }

    /// Set filters based on Instruction Pointer (IP)
    ///
    /// Only instructions in `filters` ranges will be traced.
    /// `thread_id` must be set in order to set the filters, otherwise this function will return an
    /// error.
    pub fn set_ip_filters(&mut self, filters: &[RangeInclusive<u64>]) -> Result<(), Error> {
        let thread_handle = if let Some(thread_id) = self.thread_id {
            unsafe { Owned::new(OpenThread(THREAD_GET_CONTEXT, false, thread_id)?) }
        } else {
            return Err(Error::unsupported(
                "IP filtering requires the `thread_id` to be set!",
            ));
        };

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
                    )
                })?;
        }
        log::debug!("PT filtering for IP in {filters:x?}");
        Ok(())
    }

    pub fn enable_tracing(&mut self) -> Result<(), Error> {
        self.toggle_tracing(true)
    }

    pub fn disable_tracing(&mut self) -> Result<(), Error> {
        self.toggle_tracing(false)
    }

    // If the target thread_id is not set, this function will be a best effort based on the threads
    // seen in the last decoding. Enumerating the threads for every iteration kills performances.
    // If a new thread is spawn it is traced by default. If a thread ends, the reativation will fail
    // with a log message but without returning the error.
    fn toggle_tracing(&mut self, enable: bool) -> Result<(), Error> {
        if let Some(thread_id) = self.thread_id {
            let thread_handle =
                unsafe { Owned::new(OpenThread(THREAD_GET_CONTEXT, false, thread_id)?) };
            if enable {
                self.ipt.resume_thread_trace(*thread_handle).map(|_| ())?;
            } else {
                self.ipt.pause_thread_trace(*thread_handle).map(|_| ())?;
            }
        } else {
            for thread_id in &self.last_decode_threads {
                let thread_handle =
                    match unsafe { OpenThread(THREAD_GET_CONTEXT, false, *thread_id) } {
                        Ok(handle) => unsafe { Owned::new(handle) },
                        Err(e) => {
                            log::info!("Failed to toggle tracing for thread {thread_id}: {e}");
                            continue;
                        }
                    };

                let res = if enable {
                    self.ipt.resume_thread_trace(*thread_handle)
                } else {
                    self.ipt.pause_thread_trace(*thread_handle)
                };
                let _ = res.inspect_err(|e| {
                    log::info!("Failed to toggle tracing for thread {thread_id}: {e}");
                });
            }
        }
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
        self.last_decode_threads.clear();
        #[cfg(feature = "export_raw")]
        {
            self.last_decode_trace.clear();
        }

        // get trace
        let trace_size = self
            .ipt
            .get_trace_buffer_size(*self.target_process_handle)?;
        let mut trace_buffer = TraceBuffer::with_capacity(trace_size);
        self.ipt
            .get_trace_buffer(*self.target_process_handle, &mut trace_buffer)?;

        for (header, data) in &trace_buffer {
            self.last_decode_threads.push(header.thread_id as u32);

            if self
                .thread_id
                .is_none_or(|thread_id| u64::from(thread_id) == header.thread_id)
            {
                let ptcov_decoder =
                    self.ptcov_decoders
                        .entry(header.thread_id)
                        .or_insert(ThreadCoverageDecoder {
                            decoder: PtCoverageDecoderBuilder::new()
                                .cpu(current_cpu())
                                .images(self.images)
                                .build(),
                            previous_decode_head: 0,
                        });

                log::trace!(
                    "PT previous_decode_head: {}",
                    ptcov_decoder.previous_decode_head
                );
                let mut split_buffer = Vec::new();
                let trace = if header.output_offset >= ptcov_decoder.previous_decode_head {
                    &data
                        [ptcov_decoder.previous_decode_head as usize..header.output_offset as usize]
                } else {
                    log::trace!("PT ring buffer wrapped, handling split trace");
                    split_buffer.extend(&data[ptcov_decoder.previous_decode_head as usize..]);
                    split_buffer.extend(&data[0..header.output_offset as usize]);
                    &split_buffer
                };
                ptcov_decoder.previous_decode_head = header.output_offset;

                #[cfg(feature = "export_raw")]
                {
                    self.last_decode_trace.extend(trace);
                }

                let coverage = unsafe { &mut *slice_from_raw_parts_mut(map_ptr, map_len) };

                if let Err(e) = ptcov_decoder.decoder.coverage(trace, coverage) {
                    log::warn!("PT trace decoding to coverage failed: {e:x?}");
                    coverage.fill(0.into());
                }
            }
        }

        Ok(())
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
        let file_path = traces_dir.join(format!("trace_{timestamp}"));
        let mut file = fs::File::create(&file_path)?;
        file.write_all(&self.last_decode_trace)?;

        log::trace!("Last decoded PT trace saved to {}", file_path.display());
        Ok(())
    }
}

#[derive(Debug)]
pub struct IntelPTBuilder<'a> {
    images: &'a [PtImage<'a>],
    pid: u32,
}

impl Default for IntelPTBuilder<'_> {
    fn default() -> Self {
        let pid = unsafe { GetCurrentProcessId() };
        Self { images: &[], pid }
    }
}

impl<'a> IntelPTBuilder<'a> {
    pub fn build(self) -> Result<IntelPT<'a>, Error> {
        let ipt = Ipt::open()?;

        let target_process_handle = unsafe {
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, self.pid)
                .map(|h| Owned::new(h))
        }?;

        let options = ipt::IptOption::default();
        ipt.start_process_trace(*target_process_handle, options)?;

        let mut intel_pt = IntelPT {
            ipt,
            target_process_handle,
            thread_id: None,
            ptcov_decoders: HashMap::new(),
            images: self.images,
            last_decode_threads: vec![],
            #[cfg(feature = "export_raw")]
            last_decode_trace: Vec::new(),
        };
        // Pause tracing ASAP to avoid too much trace pollution, unfortunately is not passible to
        // start tracing as "paused", and we need to start tracing in order to set IP filters.
        // todo: double check previous statement.
        let _ = intel_pt.disable_tracing();

        Ok(intel_pt)
    }

    #[must_use]
    pub fn pid(mut self, pid: u32) -> Self {
        self.pid = pid;
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
