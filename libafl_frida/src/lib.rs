pub mod asan_rt;

/// A representation of the various Frida options
#[derive(Clone, Copy, Debug)]
pub struct FridaOptions {
    enable_asan: bool,
    enable_asan_leak_detection: bool,
    enable_asan_continue_after_error: bool,
    enable_asan_allocation_backtraces: bool,
    enable_coverage: bool,
    enable_drcov: bool,
}

impl FridaOptions {
    /// Parse the frida options from the LIBAFL_FRIDA_OPTIONS environment variable.
    ///
    /// Options are ':' separated, and each options is a 'name=value' string.
    pub fn parse_env_options() -> Self {
        let mut options = Self::default();

        if let Ok(env_options) = std::env::var("LIBAFL_FRIDA_OPTIONS") {
            for option in env_options.trim().to_lowercase().split(':') {
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
                    },
                    "asan-allocation-backtraces" => {
                        options.enable_asan_allocation_backtraces = value.parse().unwrap();
                    }
                    "coverage" => {
                        options.enable_coverage = value.parse().unwrap();
                    }
                    "drcov" => {
                        options.enable_drcov = value.parse().unwrap();
                    }
                    _ => {
                        panic!("unknown FRIDA option: '{}'", option);
                    }
                }
            }
        }

        options
    }

    /// Is ASAN enabled?
    pub fn asan_enabled(&self) -> bool {
        self.enable_asan
    }

    /// Is coverage enabled?
    pub fn coverage_enabled(&self) -> bool {
        self.enable_coverage
    }

    /// Is DrCov enabled?
    pub fn drcov_enabled(&self) -> bool {
        self.enable_drcov
    }

    /// Should ASAN detect leaks
    pub fn asan_detect_leaks(&self) -> bool {
        self.enable_asan_leak_detection
    }

    /// Should ASAN continue after a memory error is detected
    pub fn asan_continue_after_error(&self) -> bool {
        self.enable_asan_continue_after_error
    }

    /// Should ASAN gather (and report) allocation-/free-site backtraces
    pub fn asan_allocation_backtraces(&self) -> bool {
        self.enable_asan_allocation_backtraces
    }
}

impl Default for FridaOptions {
    fn default() -> Self {
        Self {
            enable_asan: false,
            enable_asan_leak_detection: false,
            enable_asan_continue_after_error: false,
            enable_asan_allocation_backtraces: true,
            enable_coverage: true,
            enable_drcov: false,
        }
    }
}
