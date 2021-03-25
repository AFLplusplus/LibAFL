/// We will interact with a C++ target, so use external c functionality
extern "C" {
    /// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32;

    // libafl_targets_libfuzzer_init calls LLVMFUzzerInitialize()
    fn libafl_targets_libfuzzer_init(argc: *const i32, argv: *const *const *const u8) -> i32;
}

pub fn libfuzzer_initialize(args: &[String]) -> i32 {
    let argv: Vec<*const u8> = args.iter().map(|x| x.as_bytes().as_ptr()).collect();
    let argc = argv.len() as i32;
    unsafe {
        libafl_targets_libfuzzer_init(
            &argc as *const i32,
            &argv.as_ptr() as *const *const *const u8,
        )
    }
}

pub fn libfuzzer_test_one_input(buf: &[u8]) -> i32 {
    unsafe { LLVMFuzzerTestOneInput(buf.as_ptr(), buf.len()) }
}
