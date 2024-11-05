// Based on the example of setting hooks: Https://github.com/frida/frida-rust/blob/main/examples/gum/hook_open/src/lib.rs
use std::ffi::c_void;

use frida_gum::{interceptor::Interceptor, Gum, Module, NativePointer};
use libafl_bolts::os::windows_exceptions::{
    handle_exception, IsProcessorFeaturePresent, UnhandledExceptionFilter, EXCEPTION_POINTERS,
    PROCESSOR_FEATURE_ID,
};

unsafe extern "C" fn is_processor_feature_present_detour(feature: u32) -> bool {
    match feature {
        0x17 => false,
        _ => IsProcessorFeaturePresent(PROCESSOR_FEATURE_ID(feature)).as_bool(),
    }
}
unsafe extern "C" fn unhandled_exception_filter_detour(
    exception_pointers: *mut EXCEPTION_POINTERS,
) -> i32 {
    handle_exception(exception_pointers);
    UnhandledExceptionFilter(exception_pointers)
}
/// Initialize the hooks
pub fn initialize(gum: &Gum) {
    let module = Module::obtain(gum);
    let is_processor_feature_present =
        module.find_export_by_name(Some("kernel32.dll"), "IsProcessorFeaturePresent");
    let is_processor_feature_present = is_processor_feature_present.unwrap();
    assert!(
        !is_processor_feature_present.is_null(),
        "IsProcessorFeaturePresent not found"
    );
    let unhandled_exception_filter =
        module.find_export_by_name(Some("kernel32.dll"), "UnhandledExceptionFilter");
    let unhandled_exception_filter = unhandled_exception_filter.unwrap();
    assert!(
        !unhandled_exception_filter.is_null(),
        "UnhandledExceptionFilter not found"
    );

    let mut interceptor = Interceptor::obtain(gum);

    interceptor
        .replace(
            is_processor_feature_present,
            NativePointer(is_processor_feature_present_detour as *mut c_void),
            NativePointer(std::ptr::null_mut()),
        )
        .unwrap_or(NativePointer(std::ptr::null_mut()));

    interceptor
        .replace(
            unhandled_exception_filter,
            NativePointer(unhandled_exception_filter_detour as *mut c_void),
            NativePointer(std::ptr::null_mut()),
        )
        .unwrap_or(NativePointer(std::ptr::null_mut()));
}
