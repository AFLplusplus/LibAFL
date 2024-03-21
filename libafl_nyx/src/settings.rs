const DEFAULT_INPUT_BUFFER_SIZE: u32 = 1024 * 1024;
const DEFAULT_TIMEOUT_SECS: u8 = 2;
const DEFAULT_TIMEOUT_MICROS_SECS: u32 = 0;

#[derive(Debug, Clone, Copy)]
pub struct NyxSettings {
    pub cpu_id: u32,
    pub parent_cpu_id: Option<u32>,

    pub snap_mode: bool,
    pub parallel_mode: bool,

    pub input_buffer_size: u32,

    pub timeout_secs: u8,
    pub timeout_micro_secs: u32,
}

impl NyxSettings {
    pub fn new(
        cpu_id: u32,
        parent_cpu_id: Option<u32>,
        snap_mode: bool,
        parallel_mode: bool,
    ) -> Self {
        Self {
            cpu_id,
            parent_cpu_id,
            snap_mode,
            parallel_mode,
            input_buffer_size: DEFAULT_INPUT_BUFFER_SIZE,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            timeout_micro_secs: DEFAULT_TIMEOUT_MICROS_SECS,
        }
    }
}

impl NyxSettings {
    pub fn with_cpu_id(mut self, cpu_id: u32) -> Self {
        self.cpu_id = cpu_id;
        self
    }

    pub fn with_parent_cpu_id(mut self, parent_cpu_id: Option<u32>) -> Self {
        self.parent_cpu_id = parent_cpu_id;
        self
    }

    pub fn with_snap_mode(mut self, snap_mode: bool) -> Self {
        self.snap_mode = snap_mode;
        self
    }

    pub fn with_parallel_mode(mut self, parallel_mode: bool) -> Self {
        self.parallel_mode = parallel_mode;
        self
    }

    pub fn with_input_buffer_size(mut self, input_buffer_size: u32) -> Self {
        self.input_buffer_size = input_buffer_size;
        self
    }

    pub fn with_timeout_secs(mut self, timeout_secs: u8) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    pub fn with_timeout_micro_secs(mut self, timeout_micro_secs: u32) -> Self {
        self.timeout_micro_secs = timeout_micro_secs;
        self
    }
}
