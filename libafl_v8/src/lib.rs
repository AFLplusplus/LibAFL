//! libafl executors, observers, and other necessary components for fuzzing JavaScript targets.

// lints directly from main libafl
#![allow(incomplete_features)]
// For `type_eq`
#![cfg_attr(unstable_feature, feature(specialization))]
// For `type_id` and owned things
#![cfg_attr(unstable_feature, feature(intrinsics))]
// For `std::simd`
#![cfg_attr(unstable_feature, feature(portable_simd))]
#![warn(clippy::cargo)]
#![deny(clippy::cargo_common_metadata)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(
    clippy::unreadable_literal,
    clippy::type_repetition_in_bounds,
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation,
    clippy::used_underscore_binding,
    clippy::ptr_as_ptr,
    clippy::missing_panics_doc,
    clippy::missing_docs_in_private_items,
    clippy::module_name_repetitions,
    clippy::unreadable_literal
)]
#![cfg_attr(debug_assertions, warn(
missing_debug_implementations,
missing_docs,
//trivial_casts,
trivial_numeric_casts,
unused_extern_crates,
unused_import_braces,
unused_qualifications,
//unused_results
))]
#![cfg_attr(not(debug_assertions), deny(
missing_debug_implementations,
missing_docs,
//trivial_casts,
trivial_numeric_casts,
unused_extern_crates,
unused_import_braces,
unused_qualifications,
unused_must_use,
missing_docs,
//unused_results
))]
#![cfg_attr(
    not(debug_assertions),
    deny(
        bad_style,
        const_err,
        dead_code,
        improper_ctypes,
        non_shorthand_field_patterns,
        no_mangle_generic_items,
        overflowing_literals,
        path_statements,
        patterns_in_fns_without_body,
        private_in_public,
        unconditional_recursion,
        unused,
        unused_allocation,
        unused_comparisons,
        unused_parens,
        while_true
    )
)]
// Till they fix this buggy lint in clippy
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::borrow_deref_ref)]

pub mod executors;
pub mod loader;
pub mod observers;
pub mod values;

use std::{io, iter, sync::Arc};

use deno_core::LocalInspectorSession;
pub use deno_core::{self, v8};
pub use deno_runtime;
use deno_runtime::worker::MainWorker;
pub use executors::*;
use libafl::Error;
pub use loader::*;
pub use observers::*;
use send_wrapper::SendWrapper;
pub use tokio::runtime;
use tokio::{runtime::Runtime, sync::Mutex};
pub use values::*;

use crate::v8::{HandleScope, Local, TryCatch};

/// Runtime for the libafl v8 crate. Must be accessed from the main fuzzer thread.
pub(crate) static mut RUNTIME: Option<SendWrapper<Runtime>> = None;
/// Worker for the libafl v8 crate. Must be accessed from the v8 worker thread.
pub(crate) static mut WORKER: Option<SendWrapper<MainWorker>> = None;

/// Create an inspector for this fuzzer instance
pub(crate) fn create_inspector() -> Arc<Mutex<LocalInspectorSession>> {
    let inspector = unsafe { RUNTIME.as_ref() }
            .expect("Runtime must be initialized before creating inspector sessions; use libafl_v8::initialize_v8!")
            .block_on(async {
                let worker = unsafe { WORKER.as_mut() }
                    .expect(
                        "Worker must be initialized before creating inspector sessions; use libafl_v8::initialize_v8!",
                    );
                let mut session = worker.create_inspector_session().await;
                if let Err(e) = worker
                    .with_event_loop(Box::pin(
                        session.post_message::<()>("Profiler.enable", None),
                    ))
                    .await
                {
                    Err(Error::unknown(e.to_string()))
                } else {
                    Ok(session)
                }
            }).expect("Couldn't create the inspector");
    Arc::new(Mutex::new(inspector))
}

/// Initialize the v8 execution environment for this fuzzer instance
pub fn initialize_v8(worker: MainWorker) -> io::Result<()> {
    let runtime = runtime::Builder::new_current_thread().build()?;
    runtime.block_on(async {
        unsafe {
            WORKER = Some(SendWrapper::new(worker));
        }
    });
    unsafe {
        RUNTIME = Some(SendWrapper::new(runtime));
    }
    Ok(())
}

/// Check if the v8 execution environment is initialized for this fuzzer instance
pub fn v8_is_initialized() -> bool {
    unsafe { RUNTIME.is_some() }
}

/// Convert a JS error from a try/catch scope into a libafl error
pub fn js_err_to_libafl(scope: &mut TryCatch<HandleScope>) -> Option<Error> {
    if !scope.has_caught() {
        None
    } else {
        let exception = scope.exception().unwrap();
        let exception_string = exception
            .to_string(scope)
            .unwrap()
            .to_rust_string_lossy(scope);
        let message = if let Some(message) = scope.message() {
            message
        } else {
            return Some(Error::illegal_state(format!(
                "Provided script threw an error while executing: {}",
                exception_string
            )));
        };

        let filename = message.get_script_resource_name(scope).map_or_else(
            || "(unknown)".into(),
            |s| s.to_string(scope).unwrap().to_rust_string_lossy(scope),
        );
        let line_number = message.get_line_number(scope).unwrap_or_default();

        let source_line = message
            .get_source_line(scope)
            .map(|s| s.to_string(scope).unwrap().to_rust_string_lossy(scope))
            .unwrap();

        let start_column = message.get_start_column();
        let end_column = message.get_end_column();

        let err_underline = iter::repeat(' ')
            .take(start_column)
            .chain(iter::repeat('^').take(end_column - start_column))
            .collect::<String>();

        if let Some(stack_trace) = scope.stack_trace() {
            let stack_trace = unsafe { Local::<v8::String>::cast(stack_trace) };
            let stack_trace = stack_trace
                .to_string(scope)
                .map(|s| s.to_rust_string_lossy(scope));

            if let Some(stack_trace) = stack_trace {
                return Some(Error::illegal_state(format!(
                    "Encountered uncaught JS exception while executing: {}:{}: {}\n{}\n{}\n{}",
                    filename,
                    line_number,
                    exception_string,
                    source_line,
                    err_underline,
                    stack_trace
                )));
            }
        }
        Some(Error::illegal_state(format!(
            "Encountered uncaught JS exception while executing: {}:{}: {}\n{}\n{}",
            filename, line_number, exception_string, source_line, err_underline
        )))
    }
}
