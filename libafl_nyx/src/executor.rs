use std::{
    fmt::{self, Debug},
    marker::PhantomData,
    path::{PathBuf},
};


use libafl::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::{HasBytesVec, Input},
    observers::ObserversTuple,
};
use libnyx::{NyxProcess, NyxReturnValue};

pub type NyxResult<T> = Result<T, String>;

pub struct NyxHelper {
    nyx_process: NyxProcess,
    real_map_size: usize,
    pub map_size: usize,
    //shared memory with instruction bitmaps
    pub trace_bits: *mut u8,
}

const MAX_FILE: u32 = 1024 * 1024;
pub enum NyxProcessType {
    // stand alone mode
    ALONE,
    PARENT,
    CHILD,
}
impl NyxHelper{
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

pub struct NyxInprocessExecutor<'a, I, S, OT> {
    /// implement nyx function
    pub helper: &'a mut NyxHelper,
    observers: OT,
    phantom: PhantomData<(I, S)>,
}

impl<'a, I, S, OT> Debug for NyxInprocessExecutor<'a, I, S, OT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NyxInprocessExecutor")
            .field("helper", &self.helper)
            .finish()
    }
}

impl<'a, EM, I, S, Z, OT> Executor<EM, I, S, Z> for NyxInprocessExecutor<'a, I, S, OT>
where
    I: Input + HasBytesVec,
{
    fn post_run_reset(&mut self) {}

    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<libafl::executors::ExitKind, libafl::Error> {
        let input = input.bytes();
        self.helper.nyx_process.set_input(input, input.len() as u32);

        let ret_val = self.helper.nyx_process.exec();
        match ret_val {
            NyxReturnValue::Normal => Ok(ExitKind::Ok),
            NyxReturnValue::Crash | NyxReturnValue::Asan => Ok(ExitKind::Crash),
            NyxReturnValue::Timeout => Ok(ExitKind::Timeout),
            NyxReturnValue::InvalidWriteToPayload => {
                println!("FixMe: Nyx InvalidWriteToPayload handler is missing");
                Err(libafl::Error::ShuttingDown)
            }
            NyxReturnValue::Error => {
                println!("Error: Nyx runtime error has occured...");
                Err(libafl::Error::ShuttingDown)
            }
            NyxReturnValue::IoError => {
                // todo! *stop_soon_p = 0
                println!("Error: QEMU-nyx died...");
                Err(libafl::Error::ShuttingDown)
            }
            NyxReturnValue::Abort => {
                self.helper.nyx_process.shutdown();
                println!("Error: Nyx abort occured...");
                Err(libafl::Error::ShuttingDown)
            }
        }
    }
}

impl<'a, I, S, OT> NyxInprocessExecutor<'a, I, S, OT> {
    pub fn new(
        helper: &'a mut NyxHelper,
        observers: OT,
    ) -> NyxResult<Self> {
        Ok(Self {
            helper,
            observers,
            phantom: PhantomData,
        })
    }

    pub fn get_trace_bits(self) -> &'static mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.helper.trace_bits, self.helper.real_map_size) }
    }
}

impl<'a, I, S, OT> HasObservers<I, OT, S> for NyxInprocessExecutor<'a, I, S, OT>
where
    I: Input,
    OT: ObserversTuple<I, S>,
{
    fn observers(&self) -> &OT {
        &self.observers
    }

    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}
