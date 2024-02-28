//! Sanitizer Coverage comparison functions

use core::{mem, ptr, slice};

static mut PCS_BEG: *const usize = ptr::null();
static mut PCS_END: *const usize = ptr::null();

extern "C" {

    /// Trace an 8 bit `cmp`
    pub fn __sanitizer_cov_trace_cmp1(v0: u8, v1: u8);
    /// Trace a 16 bit `cmp`
    pub fn __sanitizer_cov_trace_cmp2(v0: u16, v1: u16);
    /// Trace a 32 bit `cmp`
    pub fn __sanitizer_cov_trace_cmp4(v0: u32, v1: u32);
    /// Trace a 64 bit `cmp`
    pub fn __sanitizer_cov_trace_cmp8(v0: u64, v1: u64);

    /// Trace an 8 bit constant `cmp`
    pub fn __sanitizer_cov_trace_const_cmp1(v0: u8, v1: u8);
    /// Trace a 16 bit constant `cmp`
    pub fn __sanitizer_cov_trace_const_cmp2(v0: u16, v1: u16);
    /// Trace a 32 bit constant `cmp`
    pub fn __sanitizer_cov_trace_const_cmp4(v0: u32, v1: u32);
    /// Trace a 64 bit constant `cmp`
    pub fn __sanitizer_cov_trace_const_cmp8(v0: u64, v1: u64);

    /// Trace a switch statement
    pub fn __sanitizer_cov_trace_switch(val: u64, cases: *const u64);

}

#[no_mangle]
unsafe extern "C" fn __sanitizer_cov_pcs_init(pcs_beg: *const usize, pcs_end: *const usize) {
    // "The Unsafe Code Guidelines also notably defines that usize and isize are respectively compatible with uintptr_t and intptr_t defined in C."
    assert!(
        pcs_beg == PCS_BEG || PCS_BEG.is_null(),
        "__sanitizer_cov_pcs_init can be called only once."
    );
    assert!(
        pcs_end == PCS_END || PCS_END.is_null(),
        "__sanitizer_cov_pcs_init can be called only once."
    );

    PCS_BEG = pcs_beg;
    PCS_END = pcs_end;
}

/// An entry to the `sanitizer_cov` `pc_table`
#[repr(C, packed)]
#[derive(Debug, PartialEq, Eq)]
pub struct PcTableEntry {
    addr: usize,
    flags: usize,
}

impl PcTableEntry {
    /// Returns whether the PC corresponds to a function entry point.
    #[must_use]
    pub fn is_function_entry(&self) -> bool {
        self.flags == 0x1
    }

    /// Returns the address associated with this PC.
    #[must_use]
    pub fn addr(&self) -> usize {
        self.addr
    }
}

/// Returns a slice containing the PC table.
#[must_use]
pub fn sanitizer_cov_pc_table() -> Option<&'static [PcTableEntry]> {
    // SAFETY: Once PCS_BEG and PCS_END have been initialized, will not be written to again. So
    // there's no TOCTOU issue.
    unsafe {
        if PCS_BEG.is_null() || PCS_END.is_null() {
            return None;
        }
        let len = PCS_END.offset_from(PCS_BEG);
        assert!(
            len > 0,
            "Invalid PC Table bounds - start: {PCS_BEG:x?} end: {PCS_END:x?}"
        );
        assert_eq!(
            len % 2,
            0,
            "PC Table size is not evens - start: {PCS_BEG:x?} end: {PCS_END:x?}"
        );
        assert_eq!(
            (PCS_BEG as usize) % mem::align_of::<PcTableEntry>(),
            0,
            "Unaligned PC Table - start: {PCS_BEG:x?} end: {PCS_END:x?}"
        );
        Some(slice::from_raw_parts(
            PCS_BEG as *const PcTableEntry,
            (len / 2).try_into().unwrap(),
        ))
    }
}
