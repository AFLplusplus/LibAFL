use typed_builder::TypedBuilder;

const DEFAULT_INPUT_BUFFER_SIZE: u32 = 1024 * 1024;
const DEFAULT_TIMEOUT_SECS: u8 = 2;
const DEFAULT_TIMEOUT_MICRO_SECS: u32 = 0;
const DEFAULT_SNAP_MODE: bool = true;

#[derive(Debug, Clone, Copy, TypedBuilder)]
pub struct NyxSettings {
    /// The CPU core for the Nyx process. The first created process will
    /// automatically be the parent process, i.e. the process that creates
    /// the fuzzing snapshot to then be also used by the child processes.
    pub cpu_id: usize,

    /// Reload the VM by using the fuzzing snapshot. You probably want
    /// this to be `true`.
    #[builder(default = DEFAULT_SNAP_MODE)]
    pub snap_mode: bool,

    /// The input buffer size (in bytes) used to pass the input to the
    /// QEMU-Nyx VM.
    ///
    /// Default is `1MB`.
    #[builder(default = DEFAULT_INPUT_BUFFER_SIZE)]
    pub input_buffer_size: u32,

    /// The timeout for a single execution in seconds (until the
    /// hypervisor restore snapshot call).
    #[builder(default = DEFAULT_TIMEOUT_SECS)]
    pub timeout_secs: u8,

    /// Additional timeout in microseconds that gets added to
    /// `timeout_secs`.
    #[builder(default = DEFAULT_TIMEOUT_MICRO_SECS)]
    pub timeout_micro_secs: u32,
}
