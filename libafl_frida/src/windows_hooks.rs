// Based on the example of setting hooks: https://github.com/frida/frida-rust/blob/main/examples/gum/hook_open/src/lib.rs
use std::{cell::UnsafeCell, sync::Mutex};

use frida_gum::{interceptor::Interceptor, Gum, Module, NativePointer};
use lazy_static::lazy_static;
use libafl::bolts::os::windows_exceptions::{handle_exception, EXCEPTION_POINTERS};

type IsProcessorFeaturePresentFunc = unsafe extern "C" fn(feature: u32) -> bool;
type UnhandledExceptionFilterFunc =
    unsafe extern "C" fn(exceptioninfo: *mut EXCEPTION_POINTERS) -> i32;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
    static ref IS_PROCESSOR_FEATURE_PRESENT: Mutex<UnsafeCell<Option<IsProcessorFeaturePresentFunc>>> =
        Mutex::new(UnsafeCell::new(None));
    static ref UNHANDLED_EXCEPTION_FILTER: Mutex<UnsafeCell<Option<UnhandledExceptionFilterFunc>>> =
        Mutex::new(UnsafeCell::new(None));
}

/// Initialize the hooks
pub fn initialize() {
    let is_processor_feature_present =
        Module::find_export_by_name(Some("kernel32.dll"), "IsProcessorFeaturePresent");
    let is_processor_feature_present = is_processor_feature_present.unwrap();
    if is_processor_feature_present.is_null() {
        panic!("IsProcessorFeaturePresent not found");
    }
    let unhandled_exception_filter =
        Module::find_export_by_name(Some("kernel32.dll"), "UnhandledExceptionFilter");
    let unhandled_exception_filter = unhandled_exception_filter.unwrap();
    if unhandled_exception_filter.is_null() {
        panic!("UnhandledExceptionFilter not found");
    }

    let mut interceptor = Interceptor::obtain(&GUM);
    use std::ffi::c_void;

    unsafe {
        *IS_PROCESSOR_FEATURE_PRESENT.lock().unwrap().get_mut() = Some(std::mem::transmute(
            interceptor
                .replace(
                    is_processor_feature_present,
                    NativePointer(is_processor_feature_present_detour as *mut c_void),
                    NativePointer(std::ptr::null_mut()),
                )
                .unwrap()
                .0,
        ));
        *UNHANDLED_EXCEPTION_FILTER.lock().unwrap().get_mut() = Some(std::mem::transmute(
            interceptor
                .replace(
                    unhandled_exception_filter,
                    NativePointer(unhandled_exception_filter_detour as *mut c_void),
                    NativePointer(std::ptr::null_mut()),
                )
                .unwrap()
                .0,
        ));
    }

    unsafe extern "C" fn is_processor_feature_present_detour(feature: u32) -> bool {
        let func = IS_PROCESSOR_FEATURE_PRESENT
            .lock()
            .unwrap()
            .get()
            .as_ref()
            .unwrap()
            .unwrap();

        let result = match feature {
            0x17 => false,
            _ => func(feature),
        };
        println!(
            "IsProcessorFeaturePresent({}) returning {}",
            feature, result
        );
        result
    }

    unsafe extern "C" fn unhandled_exception_filter_detour(
        exception_pointers: *mut EXCEPTION_POINTERS,
    ) -> i32 {
        let func = UNHANDLED_EXCEPTION_FILTER
            .lock()
            .unwrap()
            .get()
            .as_ref()
            .unwrap()
            .unwrap();

        println!("Calling handle_exception");
        handle_exception(exception_pointers);
        println!("UnhandledExceptionFilter() calling the orig function...");
        let result = func(exception_pointers);
        result
    }
}
