/// [`NyxHelper`] is used to wrap `NyxProcess`
use std::{
    fmt::{self, Debug},
    path::Path,
    time::Duration,
};

use libafl::Error;
use libnyx::{NyxProcess, NyxReturnValue};

const INIT_TIMEOUT: Duration = Duration::new(2, 0);
pub struct NyxHelper {
    pub nyx_process: NyxProcess,
    /// real size of `trace_bits`
    pub real_map_size: usize,
    // real size of the trace_bits
    pub map_size: usize,
    /// shared memory with instruction bitmaps
    pub trace_bits: *mut u8,
}

const MAX_FILE: u32 = 1024 * 1024;
#[derive(Clone, Copy, Debug)]
pub enum NyxProcessType {
    /// stand alone mode
    ALONE,
    /// parallel mode's parent, used to create snapshot
    PARENT,
    /// parallel mode's child, consume snapshot and execute
    CHILD,
}
impl NyxHelper {
    /// Create [`NyxProcess`] and do basic settings
    /// It will convert instance to parent or child using `parent_cpu_id` when set`parallel_mode`
    /// will fail if initial connection takes more than 2 seconds
    pub fn new(
        target_dir: &Path,
        cpu_id: u32,
        snap_mode: bool,
        parallel_mode: bool,
        parent_cpu_id: Option<u32>,
    ) -> Result<Self, Error> {
        NyxHelper::with_initial_timeout(
            target_dir,
            cpu_id,
            snap_mode,
            parallel_mode,
            parent_cpu_id,
            INIT_TIMEOUT,
        )
    }
    /// Create [`NyxProcess`] and do basic settings
    /// It will convert instance to parent or child using `parent_cpu_id` when set`parallel_mode`
    /// will fail if initial connection takes more than `initial_timeout` seconds
    pub fn with_initial_timeout(
        target_dir: &Path,
        cpu_id: u32,
        snap_mode: bool,
        parallel_mode: bool,
        parent_cpu_id: Option<u32>,
        initial_timeout: Duration,
    ) -> Result<Self, Error> {
        let Some(sharedir) = target_dir.to_str() else {
            return Err(Error::illegal_argument("can't convert sharedir to str"));
        };
        let work_dir = target_dir.join("workdir");
        let work_dir = work_dir.to_str().expect("unable to convert workdir to str");
        let nyx_type = if parallel_mode {
            let Some(parent_cpu_id) = parent_cpu_id else {
                return Err(Error::illegal_argument(
                    "please set parent_cpu_id in nyx parallel mode",
                ));
            };
            if cpu_id == parent_cpu_id {
                NyxProcessType::PARENT
            } else {
                NyxProcessType::CHILD
            }
        } else {
            NyxProcessType::ALONE
        };

        let nyx_process = match nyx_type {
            NyxProcessType::ALONE => NyxProcess::new(sharedir, work_dir, cpu_id, MAX_FILE, true),
            NyxProcessType::PARENT => {
                NyxProcess::new_parent(sharedir, work_dir, cpu_id, MAX_FILE, true)
            }
            NyxProcessType::CHILD => NyxProcess::new_child(sharedir, work_dir, cpu_id, cpu_id),
        };

        let mut nyx_process =
            nyx_process.map_err(|msg: String| -> Error { Error::illegal_argument(msg) })?;

        let real_map_size = nyx_process.bitmap_buffer_size();
        let map_size = ((real_map_size + 63) >> 6) << 6;
        let trace_bits = nyx_process.bitmap_buffer_mut().as_mut_ptr();
        nyx_process.option_set_reload_mode(snap_mode);
        nyx_process.option_apply();

        // default timeout for initial dry-run
        let sec = initial_timeout
            .as_secs()
            .try_into()
            .map_err(|_| -> Error { Error::illegal_argument("can't cast time's sec to u8") })?;

        let micro_sec: u32 = initial_timeout.subsec_micros();
        nyx_process.option_set_timeout(sec, micro_sec);
        nyx_process.option_apply();

        // dry run to check if qemu is spawned
        nyx_process.set_input(b"INIT", 4);
        match nyx_process.exec() {
            NyxReturnValue::Error => {
                nyx_process.shutdown();
                let msg = "Error: Nyx runtime error has occurred...";
                return Err(Error::illegal_state(msg));
            }
            NyxReturnValue::IoError => {
                let msg = "Error: QEMU-nyx died...";
                return Err(Error::illegal_state(msg));
            }
            NyxReturnValue::Abort => {
                nyx_process.shutdown();
                let msg = "Error: Nyx abort occurred...";
                return Err(Error::illegal_state(msg));
            }
            _ => {}
        }
        Ok(Self {
            nyx_process,
            real_map_size,
            map_size,
            trace_bits,
        })
    }

    /// Set a timeout for Nyx
    pub fn set_timeout(&mut self, time: Duration) {
        let sec: u8 = time
            .as_secs()
            .try_into()
            .expect("can't cast time's sec to u8");
        let micro_sec: u32 = time.subsec_micros();
        self.nyx_process.option_set_timeout(sec, micro_sec);
        self.nyx_process.option_apply();
    }
}

impl Debug for NyxHelper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NyxInprocessHelper").finish()
    }
}
