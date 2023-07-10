use std::{fmt::Debug, marker::PhantomData};

use libafl::{
    bolts::AsSlice,
    executors::{Executor, ExitKind, HasObservers},
    inputs::{HasTargetBytes, UsesInput},
    observers::{ObserversTuple, UsesObservers},
    state::{State, UsesState},
    Error,
};
use libnyx::NyxReturnValue;

use crate::helper::NyxHelper;

/// executor for nyx standalone mode
pub struct NyxExecutor<'a, S, OT> {
    /// implement nyx function
    pub helper: &'a mut NyxHelper,
    /// observers
    observers: OT,
    /// phantom data to keep generic type <I,S>
    phantom: PhantomData<S>,
}

impl<'a, S, OT> Debug for NyxExecutor<'a, S, OT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NyxInprocessExecutor")
            .field("helper", &self.helper)
            .finish()
    }
}

impl<'a, S, OT> UsesState for NyxExecutor<'a, S, OT>
where
    S: UsesInput,
{
    type State = S;
}

impl<'a, S, OT> UsesObservers for NyxExecutor<'a, S, OT>
where
    OT: ObserversTuple<S>,
    S: UsesInput,
{
    type Observers = OT;
}

impl<'a, EM, S, Z, OT> Executor<EM, Z> for NyxExecutor<'a, S, OT>
where
    EM: UsesState<State = S>,
    S: UsesInput,
    S::Input: HasTargetBytes,
    Z: UsesState<State = S>,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut Self::State,
        _mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        let input_owned = input.target_bytes();
        let input = input_owned.as_slice();
        self.helper.nyx_process.set_input(input, input.len() as u32);

        // exec will take care of trace_bits, so no need to reset
        let ret_val = self.helper.nyx_process.exec();
        match ret_val {
            NyxReturnValue::Normal => Ok(ExitKind::Ok),
            NyxReturnValue::Crash | NyxReturnValue::Asan => Ok(ExitKind::Crash),
            NyxReturnValue::Timeout => Ok(ExitKind::Timeout),
            NyxReturnValue::InvalidWriteToPayload => Err(libafl::Error::illegal_state(
                "FixMe: Nyx InvalidWriteToPayload handler is missing",
            )),
            NyxReturnValue::Error => Err(libafl::Error::illegal_state(
                "Error: Nyx runtime error has occurred...",
            )),
            NyxReturnValue::IoError => {
                // todo! *stop_soon_p = 0
                Err(libafl::Error::unknown("Error: QEMU-nyx died..."))
            }
            NyxReturnValue::Abort => {
                self.helper.nyx_process.shutdown();
                Err(libafl::Error::shutting_down())
            }
        }
    }
}

impl<'a, S, OT> NyxExecutor<'a, S, OT> {
    pub fn new(helper: &'a mut NyxHelper, observers: OT) -> Result<Self, Error> {
        Ok(Self {
            helper,
            observers,
            phantom: PhantomData,
        })
    }

    /// convert `trace_bits` ptr into real trace map
    pub fn trace_bits(self) -> &'static mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.helper.trace_bits, self.helper.real_map_size) }
    }
}

impl<'a, S, OT> HasObservers for NyxExecutor<'a, S, OT>
where
    S: State,
    OT: ObserversTuple<S>,
{
    fn observers(&self) -> &OT {
        &self.observers
    }

    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}
