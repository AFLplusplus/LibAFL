extern "C" {

    pub fn __sanitizer_cov_trace_cmp1(v0: u8, v1: u8);
    pub fn __sanitizer_cov_trace_cmp2(v0: u16, v1: u16);
    pub fn __sanitizer_cov_trace_cmp4(v0: u32, v1: u32);
    pub fn __sanitizer_cov_trace_cmp8(v0: u64, v1: u64);

    pub fn __sanitizer_cov_trace_const_cmp1(v0: u8, v1: u8);
    pub fn __sanitizer_cov_trace_const_cmp2(v0: u16, v1: u16);
    pub fn __sanitizer_cov_trace_const_cmp4(v0: u32, v1: u32);
    pub fn __sanitizer_cov_trace_const_cmp8(v0: u64, v1: u64);

    pub fn __sanitizer_cov_trace_switch(val: u64, cases: *const u64);

}
