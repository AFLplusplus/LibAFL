use std::{
    io::{Read, Seek},
    marker::PhantomData,
    os::fd::AsRawFd,
};

use libafl::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::HasTargetBytes,
    observers::{ObserversTuple, StdErrObserver, StdOutObserver, UsesObservers},
    state::{HasExecutions, State, UsesState},
    Error,
};
use libafl_bolts::{tuples::RefIndexable, AsSlice};
use libnyx::NyxReturnValue;

use crate::helper::NyxHelper;

/// executor for nyx standalone mode
pub struct NyxExecutor<S, OT> {
    /// implement nyx function
    pub helper: NyxHelper,
    /// stdout
    stdout: Option<StdOutObserver>,
    /// stderr
    // stderr: Option<StdErrObserver>,
    /// observers
    observers: OT,
    /// phantom data to keep generic type <I,S>
    phantom: PhantomData<S>,
}

impl<S, OT> UsesState for NyxExecutor<S, OT>
where
    S: State,
{
    type State = S;
}

impl<S, OT> UsesObservers for NyxExecutor<S, OT>
where
    OT: ObserversTuple<S>,
    S: State,
{
    type Observers = OT;
}

impl<EM, S, Z, OT> Executor<EM, Z> for NyxExecutor<S, OT>
where
    EM: UsesState<State = S>,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
    Z: UsesState<State = S>,
    OT: ObserversTuple<S>,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut Self::State,
        _mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        *state.executions_mut() += 1;

        let bytes = input.target_bytes();
        let buffer = bytes.as_slice();

        if buffer.len() > self.helper.nyx_process.input_buffer_size() {
            return Err(Error::illegal_state(format!(
                "Input does not fit in the Nyx input buffer.\
                You may want to increase the Nyx input buffer size: {} > {}",
                buffer.len(),
                self.helper.nyx_process.input_buffer_size()
            )));
        }

        self.helper
            .nyx_stdout
            .set_len(0)
            .map_err(|e| Error::illegal_state(format!("Failed to clear Nyx stdout: {e}")))?;

        let size = u32::try_from(buffer.len())
            .map_err(|_| Error::unsupported("Inputs larger than 4GB are not supported"))?;
        // Duplicate the file descriptor since QEMU(?) closes it and we
        // want to keep |self.helper.nyx_stdout| open.
        let hprintf_fd = nix::unistd::dup(self.helper.nyx_stdout.as_raw_fd())
            .map_err(|e| Error::illegal_state(format!("Failed to duplicate Nyx stdout fd: {e}")))?;

        self.helper.nyx_process.set_input(buffer, size);
        self.helper.nyx_process.set_hprintf_fd(hprintf_fd);

        // exec will take care of trace_bits, so no need to reset
        let exit_kind = match self.helper.nyx_process.exec() {
            NyxReturnValue::Normal => ExitKind::Ok,
            NyxReturnValue::Crash | NyxReturnValue::Asan => ExitKind::Crash,
            NyxReturnValue::Timeout => ExitKind::Timeout,
            NyxReturnValue::InvalidWriteToPayload => {
                self.helper.nyx_process.shutdown();
                return Err(Error::illegal_state(
                    "FixMe: Nyx InvalidWriteToPayload handler is missing",
                ));
            }
            NyxReturnValue::Error => {
                self.helper.nyx_process.shutdown();
                return Err(Error::illegal_state("Nyx runtime error has occurred"));
            }
            NyxReturnValue::IoError => {
                self.helper.nyx_process.shutdown();
                return Err(Error::unknown("QEMU-nyx died"));
            }
            NyxReturnValue::Abort => {
                self.helper.nyx_process.shutdown();
                return Err(Error::shutting_down());
            }
        };

        match self.stdout.as_mut() {
            Some(ob) => {
                let mut stdout = Vec::new();
                self.helper.nyx_stdout.rewind()?;
                self.helper
                    .nyx_stdout
                    .read_to_end(&mut stdout)
                    .map_err(|e| Error::illegal_state(format!("Failed to read Nyx stdout: {e}")))?;

                ob.observe_stdout(&stdout);
            }
            None => (),
        }

        Ok(exit_kind)
    }
}

impl<S, OT> NyxExecutor<S, OT> {
    /// convert `trace_bits` ptr into real trace map
    pub fn trace_bits(self) -> &'static mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(self.helper.bitmap_buffer, self.helper.bitmap_size)
        }
    }
}

pub struct NyxExecutorBuilder {
    stdout: Option<StdOutObserver>,
    // stderr: Option<StdErrObserver>,
}

impl NyxExecutorBuilder {
    pub fn new() -> Self {
        Self {
            stdout: None,
            // stderr: None,
        }
    }

    pub fn stdout(&mut self, stdout: StdOutObserver) -> &mut Self {
        self.stdout = Some(stdout);
        self
    }

    /*
    pub fn stderr(&mut self, stderr: StdErrObserver) -> &mut Self {
        self.stderr = Some(stderr);
        self
    }
    */

    pub fn build<S, OT>(&self, helper: NyxHelper, observers: OT) -> NyxExecutor<S, OT> {
        NyxExecutor {
            helper,
            stdout: self.stdout.clone(),
            // stderr: self.stderr.clone(),
            observers,
            phantom: PhantomData,
        }
    }
}

impl<S, OT> HasObservers for NyxExecutor<S, OT>
where
    S: State,
    OT: ObserversTuple<S>,
{
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}
