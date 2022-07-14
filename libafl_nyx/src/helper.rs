/// [`NyxHelper`] is used to wrap `NyxProcess`
use std::{
    fmt::{self, Debug},
    path::Path,
};

use libnyx::{NyxProcess, NyxReturnValue};

pub type NyxResult<T> = Result<T, String>;

pub struct NyxHelper {
    pub nyx_process: NyxProcess,
    /// real size of trace_bits
    pub real_map_size: usize,
    // real size of the trace_bits
    pub map_size: usize,
    /// shared memory with instruction bitmaps
    pub trace_bits: *mut u8,
}

const MAX_FILE: u32 = 1024 * 1024;
#[derive(Clone, Copy)]
pub enum NyxProcessType {
    /// stand alone mode
    ALONE,
    /// parallel mode's parent, used to create snapshot
    PARENT,
    /// parallel mode's child, consume snapshot and execute
    CHILD,
}
impl NyxHelper {
    /// create `NyxProcess` and do basic settings
    pub fn new(
        target_dir: &Path,
        cpu_id: u32,
        snap_mode: bool,
        nyx_type: NyxProcessType,
    ) -> NyxResult<Self> {
        let sharedir = target_dir.to_str().unwrap();
        let workdir = target_dir.join("workdir");
        let workdir = workdir.to_str().unwrap();
        let mut nyx_process = match nyx_type {
            NyxProcessType::ALONE => NyxProcess::new(sharedir, workdir, cpu_id, MAX_FILE, true)?,
            NyxProcessType::PARENT => {
                NyxProcess::new_parent(sharedir, workdir, cpu_id, MAX_FILE, true)?
            }
            NyxProcessType::CHILD => NyxProcess::new_child(sharedir, workdir, cpu_id, MAX_FILE)?,
        };
        let real_map_size = nyx_process.bitmap_buffer_size();
        let map_size = ((real_map_size + 63) >> 6) << 6;
        let trace_bits = nyx_process.bitmap_buffer_mut().as_mut_ptr();
        nyx_process.option_set_reload_mode(snap_mode);
        nyx_process.option_apply();
        nyx_process.option_set_timeout(2, 0);
        nyx_process.option_apply();
        nyx_process.set_input(b"INIT", 4);
        match nyx_process.exec() {
            NyxReturnValue::Error => {
                nyx_process.shutdown();
                let msg = "Error: Nyx runtime error has occured...";
                return Err(msg.to_string());
            }
            NyxReturnValue::IoError => {
                let msg = "Error: QEMU-nyx died...";
                return Err(msg.to_string());
            }
            NyxReturnValue::Abort => {
                nyx_process.shutdown();
                let msg = "Error: Nyx abort occured...";
                return Err(msg.to_string());
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
}

impl Debug for NyxHelper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NyxInprocessHelper").finish()
    }
}
