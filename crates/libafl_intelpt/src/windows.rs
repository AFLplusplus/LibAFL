#![allow(dead_code)] // todo remove

use alloc::vec::Vec;
use core::ptr;
use std::{io, prelude::rust_2015::String};

pub use ptcov::PtCoverageDecoder;
use raw_cpuid::CpuId;
use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_NO_BUFFERING, FILE_FLAG_SEQUENTIAL_SCAN,
        FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
    },
};

/// Intel Processor Trace (PT)
#[derive(Debug)]
pub struct IntelPT<'a> {
    ipt_handle: HANDLE,

    previous_decode_head: u64,
    ptcov_decoder: PtCoverageDecoder<'a>,
    #[cfg(feature = "export_raw")]
    last_decode_trace: Vec<u8>,
}

pub(crate) fn availability_in_windows() -> Result<(), String> {
    let mut reasons = Vec::new();

    if let Err(e) = get_ipt_handle() {
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

fn get_ipt_handle() -> io::Result<HANDLE> {
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

    Ok(handle)
}

#[cfg(test)]
mod tests {}
