/*!
The frida executor is a binary-only mode for `LibAFL`.
It can report coverage and, on supported architecutres, even reports memory access errors.
*/

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

/// The frida-asan allocator
#[cfg(unix)]
pub mod alloc;

#[cfg(unix)]
pub mod asan;

pub mod coverage_rt;

#[cfg(feature = "cmplog")]
/// The frida cmplog runtime
pub mod cmplog_rt;

/// The `LibAFL` firda helper
pub mod helper;

pub mod drcov_rt;

/// The frida executor
pub mod executor;

/// Utilities
#[cfg(unix)]
pub mod utils;

// for parsing asan and cmplog cores
use libafl::bolts::os::{CoreId, Cores};

// for getting current core_id
use core_affinity::get_core_ids;

/// A representation of the various Frida options
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct FridaOptions {
    enable_asan: bool,
    enable_asan_leak_detection: bool,
    enable_asan_continue_after_error: bool,
    enable_asan_allocation_backtraces: bool,
    asan_max_allocation: usize,
    asan_max_total_allocation: usize,
    asan_max_allocation_panics: bool,
    enable_coverage: bool,
    enable_drcov: bool,
    instrument_suppress_locations: Option<Vec<(String, usize)>>,
    enable_cmplog: bool,
}

impl FridaOptions {
    /// Parse the frida options from the "`LIBAFL_FRIDA_OPTIONS`" environment variable.
    ///
    /// Options are `:` separated, and each options is a `name=value` string.
    ///
    /// # Panics
    /// Panics, if no `=` sign exists in input, or or `value` behind `=` has zero length.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn parse_env_options() -> Self {
        let mut options = Self::default();
        let mut asan_cores = None;
        let mut cmplog_cores = None;

        if let Ok(env_options) = std::env::var("LIBAFL_FRIDA_OPTIONS") {
            for option in env_options.trim().split(':') {
                let (name, mut value) =
                    option.split_at(option.find('=').expect("Expected a '=' in option string"));
                value = value.get(1..).unwrap();
                match name {
                    "asan" => {
                        options.enable_asan = value.parse().unwrap();
                    }
                    "asan-detect-leaks" => {
                        options.enable_asan_leak_detection = value.parse().unwrap();
                    }
                    "asan-continue-after-error" => {
                        options.enable_asan_continue_after_error = value.parse().unwrap();
                    }
                    "asan-allocation-backtraces" => {
                        options.enable_asan_allocation_backtraces = value.parse().unwrap();
                    }
                    "asan-max-allocation" => {
                        options.asan_max_allocation = value.parse().unwrap();
                    }
                    "asan-max-total-allocation" => {
                        options.asan_max_total_allocation = value.parse().unwrap();
                    }
                    "asan-max-allocation-panics" => {
                        options.asan_max_allocation_panics = value.parse().unwrap();
                    }
                    "asan-cores" => {
                        asan_cores = Cores::from_cmdline(value).ok();
                    }
                    "instrument-suppress-locations" => {
                        options.instrument_suppress_locations = Some(
                            value
                                .split(',')
                                .map(|val| {
                                    let (module, offset) = val.split_at(
                                        val.find('@')
                                            .expect("Expected an '@' in location specifier"),
                                    );
                                    (
                                        module.to_string(),
                                        usize::from_str_radix(
                                            offset.get(1..).unwrap().trim_start_matches("0x"),
                                            16,
                                        )
                                        .unwrap(),
                                    )
                                })
                                .collect(),
                        );
                    }
                    "coverage" => {
                        options.enable_coverage = value.parse().unwrap();
                    }
                    "drcov" => {
                        options.enable_drcov = value.parse().unwrap();
                        #[cfg(not(target_arch = "aarch64"))]
                        assert!(
                            !options.enable_drcov,
                            "DrCov is not currently supported on targets other than aarch64"
                        );
                    }
                    "cmplog" => {
                        options.enable_cmplog = value.parse().unwrap();
                        #[cfg(not(target_arch = "aarch64"))]
                        assert!(
                            !options.enable_cmplog,
                            "cmplog is not currently supported on targets other than aarch64"
                        );

                        if options.enable_cmplog {
                            assert!(cfg!(feature = "cmplog"), "cmplog feature is disabled!");
                        }
                    }
                    "cmplog-cores" => {
                        cmplog_cores = Cores::from_cmdline(value).ok();
                    }
                    _ => {
                        panic!("unknown FRIDA option: '{}'", option);
                    }
                }
            } // end of for loop

            if options.enable_asan {
                if let Some(asan_cores) = asan_cores {
                    let core_ids = get_core_ids().unwrap();
                    assert_eq!(
                        core_ids.len(),
                        1,
                        "Client should only be bound to a single core"
                    );
                    let core_id: CoreId = core_ids[0].into();
                    options.enable_asan = asan_cores.ids.contains(&core_id);
                }
            }
            if options.enable_cmplog {
                if let Some(cmplog_cores) = cmplog_cores {
                    let core_ids = get_core_ids().unwrap();
                    assert_eq!(
                        core_ids.len(),
                        1,
                        "Client should only be bound to a single core"
                    );
                    let core_id = core_ids[0].into();
                    options.enable_cmplog = cmplog_cores.ids.contains(&core_id);
                }
            }
        }
        options
    }

    /// Is ASAN enabled?
    #[must_use]
    #[inline]
    pub fn asan_enabled(&self) -> bool {
        self.enable_asan
    }

    /// Is coverage enabled?
    #[must_use]
    #[inline]
    pub fn coverage_enabled(&self) -> bool {
        self.enable_coverage
    }

    /// Is `DrCov` enabled?
    #[must_use]
    #[inline]
    pub fn drcov_enabled(&self) -> bool {
        self.enable_drcov
    }

    /// Is `CmpLog` enabled?
    #[must_use]
    #[inline]
    pub fn cmplog_enabled(&self) -> bool {
        self.enable_cmplog
    }

    /// Should ASAN detect leaks
    #[must_use]
    #[inline]
    pub fn asan_detect_leaks(&self) -> bool {
        self.enable_asan_leak_detection
    }

    /// The maximum size that the ASAN allocator should allocate
    #[must_use]
    #[inline]
    pub fn asan_max_allocation(&self) -> usize {
        self.asan_max_allocation
    }

    /// The maximum total allocation size that the ASAN allocator should allocate
    #[must_use]
    #[inline]
    pub fn asan_max_total_allocation(&self) -> usize {
        self.asan_max_total_allocation
    }

    /// Should we panic if the max ASAN allocation size is exceeded
    #[must_use]
    #[inline]
    pub fn asan_max_allocation_panics(&self) -> bool {
        self.asan_max_allocation_panics
    }

    /// Should ASAN continue after a memory error is detected
    #[must_use]
    #[inline]
    pub fn asan_continue_after_error(&self) -> bool {
        self.enable_asan_continue_after_error
    }

    /// Should ASAN gather (and report) allocation-/free-site backtraces
    #[must_use]
    #[inline]
    pub fn asan_allocation_backtraces(&self) -> bool {
        self.enable_asan_allocation_backtraces
    }

    /// Whether stalker should be enabled. I.e. whether at least one stalker requiring option is
    /// enabled.
    #[must_use]
    #[inline]
    pub fn stalker_enabled(&self) -> bool {
        self.enable_asan || self.enable_coverage || self.enable_drcov
    }

    /// A list of locations which will not be instrumented for ASAN or coverage purposes
    #[must_use]
    pub fn dont_instrument_locations(&self) -> Option<Vec<(String, usize)>> {
        self.instrument_suppress_locations.clone()
    }
}

impl Default for FridaOptions {
    fn default() -> Self {
        Self {
            enable_asan: false,
            enable_asan_leak_detection: false,
            enable_asan_continue_after_error: false,
            enable_asan_allocation_backtraces: false,
            asan_max_allocation: 1 << 30,
            asan_max_total_allocation: 1 << 32,
            asan_max_allocation_panics: false,
            enable_coverage: true,
            enable_drcov: false,
            instrument_suppress_locations: None,
            enable_cmplog: false,
        }
    }
}
