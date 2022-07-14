use libafl::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::{HasBytesVec, Input},
    observers::ObserversTuple,
};
use libnyx::NyxReturnValue;
use std::fmt::Debug;
/// executor for nyx
use std::marker::PhantomData;

use crate::helper::{NyxHelper, NyxResult};

/// executor for nyx standalone mode
pub struct NyxStandaloneExecutor<'a, I, S, OT> {
    /// implement nyx function
    pub helper: &'a mut NyxHelper,
    /// observers
    observers: OT,
    /// phantom data to keep generic type <I,S>
    phantom: PhantomData<(I, S)>,
}

impl<'a, I, S, OT> Debug for NyxStandaloneExecutor<'a, I, S, OT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NyxInprocessExecutor")
            .field("helper", &self.helper)
            .finish()
    }
}

impl<'a, EM, I, S, Z, OT> Executor<EM, I, S, Z> for NyxStandaloneExecutor<'a, I, S, OT>
where
    I: Input + HasBytesVec,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<libafl::executors::ExitKind, libafl::Error> {
        let input = input.bytes();
        self.helper.nyx_process.set_input(input, input.len() as u32);

        // exec will take care of trace_bits, so no need to reset
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

impl<'a, I, S, OT> NyxStandaloneExecutor<'a, I, S, OT> {
    pub fn new(helper: &'a mut NyxHelper, observers: OT) -> NyxResult<Self> {
        Ok(Self {
            helper,
            observers,
            phantom: PhantomData,
        })
    }

    /// convert `trace_bits` ptr into real trace map
    pub fn get_trace_bits(self) -> &'static mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.helper.trace_bits, self.helper.real_map_size) }
    }
}

impl<'a, I, S, OT> HasObservers<I, OT, S> for NyxStandaloneExecutor<'a, I, S, OT>
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
