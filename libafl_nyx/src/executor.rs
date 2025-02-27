use core::marker::PhantomData;
use std::{
    io::{Read, Seek},
    os::fd::AsRawFd,
};

use libafl::{
    Error,
    executors::{Executor, ExitKind, HasObservers, HasTimeout},
    inputs::HasTargetBytes,
    observers::{ObserversTuple, StdOutObserver},
    state::HasExecutions,
};
use libafl_bolts::{AsSlice, tuples::RefIndexable};
use libnyx::NyxReturnValue;

use crate::{cmplog::CMPLOG_ENABLED, helper::NyxHelper};

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

impl NyxExecutor<(), ()> {
    /// Create a builder for [`NyxExeuctor`]
    #[must_use]
    pub fn builder() -> NyxExecutorBuilder {
        NyxExecutorBuilder::new()
    }
}

impl<EM, I, OT, S, Z> Executor<EM, I, S, Z> for NyxExecutor<S, OT>
where
    S: HasExecutions,
    I: HasTargetBytes,
    OT: ObserversTuple<I, S>,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _mgr: &mut EM,
        input: &I,
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

        unsafe {
            if CMPLOG_ENABLED == 1 {
                self.helper.nyx_process.option_set_redqueen_mode(true);
                self.helper.nyx_process.option_apply();
            }
        }

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

        if let Some(ob) = self.stdout.as_mut() {
            let mut stdout = Vec::new();
            self.helper.nyx_stdout.rewind()?;
            self.helper
                .nyx_stdout
                .read_to_end(&mut stdout)
                .map_err(|e| Error::illegal_state(format!("Failed to read Nyx stdout: {e}")))?;

            ob.observe(&stdout);
        }

        unsafe {
            if CMPLOG_ENABLED == 1 {
                self.helper.nyx_process.option_set_redqueen_mode(false);
                self.helper.nyx_process.option_apply();
            }
        }

        Ok(exit_kind)
    }
}

impl<S, OT> HasTimeout for NyxExecutor<S, OT> {
    fn timeout(&self) -> core::time::Duration {
        self.helper.timeout
    }

    fn set_timeout(&mut self, timeout: core::time::Duration) {
        let micros = 1000000;
        let mut timeout_secs = timeout.as_secs();
        let mut timeout_micros = timeout.as_micros() - u128::from(timeout.as_secs() * micros);
        // since timeout secs is a u8 -> convert any overflow into micro secs
        if timeout_secs > 255 {
            timeout_micros = u128::from((timeout_secs - 255) * micros);
            timeout_secs = 255;
        }

        self.helper.timeout = timeout;

        self.helper
            .set_timeout(timeout_secs as u8, timeout_micros as u32);
    }
}

impl<S, OT> NyxExecutor<S, OT> {
    /// Convert `trace_bits` ptr into real trace map
    ///
    /// # Safety
    /// Mutable borrow may only be used once at a time.
    pub unsafe fn trace_bits(self) -> &'static mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(self.helper.bitmap_buffer, self.helper.bitmap_size)
        }
    }
}

pub struct NyxExecutorBuilder {
    stdout: Option<StdOutObserver>,
    // stderr: Option<StdErrObserver>,
}

impl Default for NyxExecutorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NyxExecutorBuilder {
    #[must_use]
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

impl<S, OT> HasObservers for NyxExecutor<S, OT> {
    type Observers = OT;

    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}
