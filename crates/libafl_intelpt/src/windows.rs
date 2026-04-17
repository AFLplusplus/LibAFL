pub use ptcov::PtCoverageDecoder;
use raw_cpuid::CpuId;

/// Number of address filters available on the running CPU
pub fn nr_addr_filters() -> Result<u8, &'static str> {
    let cpuid = CpuId::new();
    cpuid
        .get_processor_trace_info()
        .ok_or("Failed to read CPU Processor Trace Info")
        .map(|pti| pti.configurable_address_ranges())
}

// /// Intel Processor Trace (PT)
// #[derive(Debug)]
// pub struct IntelPT<'a> {
//     previous_decode_head: u64,
//     ptcov_decoder: PtCoverageDecoder<'a>,
//     #[cfg(feature = "export_raw")]
//     last_decode_trace: Vec<u8>,
// }
