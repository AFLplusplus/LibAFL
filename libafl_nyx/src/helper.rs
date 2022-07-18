/// [`NyxHelper`] is used to wrap `NyxProcess`
use std::{
    fmt::{self, Debug},
    path::Path, sync::{atomic::{AtomicU32, Ordering}, Arc, Mutex}, slice::SliceIndex,
};

use libnyx::{NyxProcess, NyxReturnValue};

pub type NyxResult<T> = Result<T, String>;

static mut NYX_PROCESS_NUM: AtomicU32= AtomicU32::new(0);
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
    /// It will convert instance to parent or child when set`parallel_mode`
    pub fn new(
        target_dir: &Path,
        cpu_id: u32,
        snap_mode: bool,
        parallel_mode: bool,
    ) -> NyxResult<Self> {
        let sharedir = target_dir.to_str().unwrap();
        let workdir = target_dir.join("workdir");
        let workdir = workdir.to_str().unwrap();
        let mut child_work_id:Option<u32> = None;
        let nyx_type = match parallel_mode{
            true =>{
                unsafe{
                    let process_num = NYX_PROCESS_NUM.fetch_add(1, Ordering::SeqCst);
                if process_num == 0{
                    println!("parent!");
                    NyxProcessType::PARENT
                }else{
                    println!("child!");
                    child_work_id = Some(process_num);
                    NyxProcessType::CHILD
                }
            }
            }
            false => NyxProcessType::ALONE
        };
        let mut nyx_process = match nyx_type {
            NyxProcessType::ALONE => NyxProcess::new(sharedir, workdir, cpu_id, MAX_FILE, true)?,
            NyxProcessType::PARENT => {
                NyxProcess::new_parent(sharedir, workdir, cpu_id, MAX_FILE, true)?
            }
            NyxProcessType::CHILD => 
            {
                if let Some(worker_id) = child_work_id {
                NyxProcess::new_child(sharedir, workdir, cpu_id, worker_id)?
                }else{
                    return Err("can't get worker id".to_string())
                }
            }
        };

        let real_map_size = nyx_process.bitmap_buffer_size();
        let map_size = ((real_map_size + 63) >> 6) << 6;
        let trace_bits = nyx_process.bitmap_buffer_mut().as_mut_ptr();
        nyx_process.option_set_reload_mode(snap_mode);
        nyx_process.option_apply();

        // default timeout for initial dry-run
        nyx_process.option_set_timeout(2, 0);
        nyx_process.option_apply();

        // dry run to test the connection
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

    /// set timeout time to (`sec` + 10^(-6)*`micro_sec`) sec
    pub fn set_timeout(mut self, sec: u8, micro_sec: u32) {
        self.nyx_process.option_set_timeout(sec, micro_sec);
        self.nyx_process.option_apply();
    }
}

impl Debug for NyxHelper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NyxInprocessHelper").finish()
    }
}
