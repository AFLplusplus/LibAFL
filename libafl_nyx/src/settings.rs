use typed_builder::TypedBuilder;

const DEFAULT_INPUT_BUFFER_SIZE: u32 = 1024 * 1024;
const DEFAULT_TIMEOUT_SECS: u8 = 2;
const DEFAULT_TIMEOUT_MICRO_SECS: u32 = 0;

#[derive(Debug, Clone, Copy, TypedBuilder)]
pub struct NyxSettings {
    pub cpu_id: u32,
    pub parent_cpu_id: Option<u32>,

    pub snap_mode: bool,
    pub parallel_mode: bool,

    #[builder(default = DEFAULT_INPUT_BUFFER_SIZE)]
    pub input_buffer_size: u32,

    #[builder(default = DEFAULT_TIMEOUT_SECS)]
    pub timeout_secs: u8,

    #[builder(default = DEFAULT_TIMEOUT_MICRO_SECS)]
    pub timeout_micro_secs: u32,
}
