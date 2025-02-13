use typed_builder::TypedBuilder;

const DEFAULT_INPUT_BUFFER_SIZE: usize = 1024 * 1024;
const DEFAULT_TIMEOUT_SECS: u8 = 2;
const DEFAULT_TIMEOUT_MICRO_SECS: u32 = 0;
const DEFAULT_SNAP_MODE: bool = true;

#[derive(Debug, Clone, Copy, TypedBuilder)]
pub struct NyxSettings {
    /// The CPU core for the Nyx process.
    ///
    /// Depending on the value of `parent_cpu_id`, the created Nyx process
    /// will be one of the following types:
    /// * Standalone: `parent_cpu_id.is_none()`.
    /// * Parent: `parent_cpu_id.is_some_and(|parent_cpu_id| parent_cpu_id == cpu_id)`.
    /// * Child: `parent_cpu_id.is_some_and(|parent_cpu_id| parent_cpu_id != cpu_id)`.
    pub cpu_id: usize,

    /// The CPU core for the Nyx parent process. The parent process
    /// creates the fuzzing snapshot that can then be used by the child
    /// processes.
    ///
    /// Not specifying this will start the Nyx process in standalone mode.
    pub parent_cpu_id: Option<usize>,

    /// Reload the VM by using the fuzzing snapshot. You probably want
    /// this to be `true`.
    #[builder(default = DEFAULT_SNAP_MODE)]
    pub snap_mode: bool,

    /// The input buffer size (in bytes) used to pass the input to the
    /// QEMU-Nyx VM.
    ///
    /// Default is `1MB`.
    #[builder(default = DEFAULT_INPUT_BUFFER_SIZE)]
    pub input_buffer_size: usize,

    /// The timeout for a single execution in seconds (until the
    /// hypervisor restore snapshot call).
    #[builder(default = DEFAULT_TIMEOUT_SECS)]
    pub timeout_secs: u8,

    /// Additional timeout in microseconds that gets added to
    /// `timeout_secs`.
    #[builder(default = DEFAULT_TIMEOUT_MICRO_SECS)]
    pub timeout_micro_secs: u32,
}
