use std::{
    ffi::OsString,
    fmt::{self, Debug},
    path::{Path, PathBuf}, marker::PhantomData,
};

use libafl::{
    bolts::ownedref::IntoOwned,
    executors::{with_observers, Executor, ExitKind},
    inputs::{HasBytesVec, HasTargetBytes, Input},
    observers::ObserversTuple,
};
use libnyx::NyxReturnValue;

use crate::nyx_bridge::{nyx_new, nyx_new_child, nyx_new_parent, NyxResult};

// don't use libnyx!!! use nyx_bridge instead to avoid confusion
use super::nyx_bridge::NyxProcess;

pub struct NyxHelper {
    nyx_process: NyxProcess,
    real_map_size: usize,
    pub map_size: usize,
    //shared memory with instruction bitmaps
    pub trace_bits: *mut u8,
}

const MAX_FILE: u32 = 1 * 1024 * 1024;
pub enum NyxProcessType {
    // stand alone mode
    ALONE,
    PARENT,
    CHILD,
}
impl NyxHelper {
    pub fn new(
        target_dir: PathBuf,
        cpu_id: u32,
        snap_mode: bool,
        nyx_type: NyxProcessType,
    ) -> NyxResult<Self> {
        let sharedir = target_dir.to_str().unwrap();
        let workdir = target_dir.join("workdir");
        let workdir = workdir.to_str().unwrap();
        let mut nyx_process = match nyx_type {
            NyxProcessType::ALONE => nyx_new(sharedir, workdir, cpu_id, MAX_FILE, true)?,
            NyxProcessType::PARENT => nyx_new_parent(sharedir, workdir, cpu_id, MAX_FILE, true)?,
            NyxProcessType::CHILD => nyx_new_child(sharedir, workdir, cpu_id, MAX_FILE)?,
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

    fn pre_exec(&mut self) {
        let buf: &mut [u8];
        unsafe {
            buf = core::slice::from_raw_parts_mut(self.trace_bits, self.map_size as usize);
        }
        // reset trace map bits
        buf.fill(0);
    }
}

impl Debug for NyxHelper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NyxInprocessHelper").finish()
    }
}
pub struct NyxInprocessExecutor
{
    /// implement nyx function
    pub helper: NyxHelper,
}

impl Debug for NyxInprocessExecutor
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NyxInprocessExecutor")
            .field("helper", &self.helper)
            .finish()
    }
}

impl<EM, I, S, Z> Executor<EM, I, S, Z> for NyxInprocessExecutor
where
    I: Input + HasBytesVec
{
    fn post_run_reset(&mut self) {}

    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<libafl::executors::ExitKind, libafl::Error> {
        let input = input.bytes();
        self.helper.nyx_process.set_input(input, input.len() as u32);

        let ret_val = self.helper.nyx_process.exec();
        match ret_val {
            NyxReturnValue::Normal => return Ok(ExitKind::Ok),
            NyxReturnValue::Crash | NyxReturnValue::Asan => return Ok(ExitKind::Crash),
            NyxReturnValue::Timeout => return Ok(ExitKind::Timeout),
            NyxReturnValue::InvalidWriteToPayload => {
                println!("FixMe: Nyx InvalidWriteToPayload handler is missing");
                return Err(libafl::Error::ShuttingDown);
            }
            NyxReturnValue::Error => {
                println!("Error: Nyx runtime error has occured...");
                return Err(libafl::Error::ShuttingDown);
            }
            NyxReturnValue::IoError => {
                // todo! *stop_soon_p = 0
                println!("Error: QEMU-nyx died...");
                return Err(libafl::Error::ShuttingDown);
            }
            NyxReturnValue::Abort => {
                self.helper.nyx_process.shutdown();
                println!("Error: Nyx abort occured...");
                return Err(libafl::Error::ShuttingDown);
            }
        }
    }
}


impl NyxInprocessExecutor{
        pub fn new(target_dir:PathBuf, cpu_id:u32, snap_mode:bool) -> NyxResult<Self>{
            let helper = NyxHelper::new(target_dir, cpu_id, snap_mode, NyxProcessType::ALONE)?;
            Ok(Self{
                helper,
            })

        }

        pub fn get_trace_bits(self) -> &'static mut [u8]{
            unsafe{
            std::slice::from_raw_parts_mut(self.helper.trace_bits, self.helper.real_map_size)            
            }
        }
    }