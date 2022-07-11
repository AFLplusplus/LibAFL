use std::{
    ffi::OsString,
    fmt::{self, Debug},
};

use libafl::{
    executors::{with_observers, Executor},
    inputs::Input,
    observers::ObserversTuple,
};

use crate::nyx_bridge::{nyx_new, nyx_new_child, nyx_new_parent, NyxResult};

// don't use libnyx!!! use nyx_bridge instead to avoid confusion
use super::nyx_bridge::NyxProcess;

pub struct NyxInprocessHelper {
    nyx_process: NyxProcess,
    real_map_size: usize,
    map_size: usize,
    //shared memory with instruction bitmaps
    trace_bits: *mut u8,
}

const MAX_FILE: u32 = 1 * 1024 * 1024;
enum NyxProcessType {
    // stand alone mode
    ALONE,
    PARENT,
    CHILD,
}
impl NyxInprocessHelper {
    fn new(
        sharedir: OsString,
        workdir: OsString,
        cpu_id: u32,
        enable_snap_mode: bool,
        nyx_type: NyxProcessType,
    ) -> NyxResult<Self> {
        let sharedir = sharedir.to_str().unwrap();
        let workdir = workdir.to_str().unwrap();
        let mut nyx_process = match nyx_type {
            NyxProcessType::ALONE => nyx_new(sharedir, workdir, cpu_id, MAX_FILE, true)?,
            NyxProcessType::PARENT => nyx_new_parent(sharedir, workdir, cpu_id, MAX_FILE, true)?,
            NyxProcessType::CHILD => nyx_new_child(sharedir, workdir, cpu_id, MAX_FILE)?,
        };
        let real_map_size = nyx_process.bitmap_buffer_size();
        let map_size = ((real_map_size + 63) >> 6) << 6;
        let trace_bits = nyx_process.bitmap_buffer_mut().as_mut_ptr();
        nyx_process.option_set_reload_mode(enable_snap_mode);
        nyx_process.option_apply();
        nyx_process.option_set_timeout(2, 0);
        nyx_process.option_apply();

        Ok(Self {
            nyx_process,
            real_map_size,
            map_size,
            trace_bits,
        })
    }
}

impl Debug for NyxInprocessHelper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NyxInprocessHelper").finish()
    }
}
struct NyxInprocessExecutor<I, OT, S>
where
    I: Input,
    OT: ObserversTuple<I, S>,
{
    /// implement nyx function
    helper: NyxInprocessHelper,
    map_size: u32,
    real_map_size: u32,
    Input: I,
    State: S,
    /// record all observers
    observers: OT,
}

impl<I, OT, S> Debug for NyxInprocessExecutor<I, OT, S>
where
    I: Input,
    OT: ObserversTuple<I, S>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NyxInprocessExecutor")
            .field("helper", &self.helper)
            .field("observers", &self.observers)
            .finish()
    }
}

impl<EM, I, S, Z, OT> Executor<EM, I, S, Z> for NyxInprocessExecutor<I, OT, S>
where
    I: Input + fmt::Debug,
    OT: ObserversTuple<I, S>,
{
    fn post_run_reset(&mut self) {}

    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<libafl::executors::ExitKind, libafl::Error> {
        todo!()
    }
}
