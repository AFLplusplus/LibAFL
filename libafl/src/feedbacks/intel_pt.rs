use alloc::borrow::Cow;
use std::{
    sync::{Arc, Mutex},
    vec::Vec,
};

use libafl_bolts::{Error, Named};
use similar::{capture_diff_slices, Algorithm, DiffOp};

use crate::{
    events::EventFirer, executors::ExitKind, feedbacks::Feedback, observers::ObserversTuple,
    state::State,
};

#[derive(Debug)]
pub struct IntelPTFeedback {
    trace: Arc<Mutex<Vec<u8>>>,
    past_traces: Vec<Vec<u8>>,
    avg_score: u128,
}

impl IntelPTFeedback {
    pub fn new(trace: Arc<Mutex<Vec<u8>>>) -> Self {
        Self {
            trace,
            past_traces: vec![],
            avg_score: 0,
        }
    }
}

impl Named for IntelPTFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("IntelPTObserver")
    }
}

impl<S> Feedback<S> for IntelPTFeedback
where
    S: State,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        if self.past_traces.is_empty() {
            return Ok(true);
        }

        let trace = self.trace.lock().unwrap();

        let mut tot_score = 0u128;
        for pt in &self.past_traces {
            let diff = capture_diff_slices(Algorithm::Myers, &trace, &pt);
            let score = diff
                .iter()
                .map(|e| match e {
                    DiffOp::Equal { .. } => 0,
                    DiffOp::Delete { .. } => 0,
                    DiffOp::Insert { new_len, .. } => *new_len,
                    DiffOp::Replace { new_len, .. } => *new_len,
                })
                .sum::<usize>();
            tot_score += score as u128;
        }

        let weighted_score = tot_score / self.past_traces.len() as u128;

        self.past_traces.push(trace.clone());
        let n = self.past_traces.len() as u128;
        self.avg_score = self.avg_score * (n - 1) / n + weighted_score / n;

        if weighted_score > self.avg_score * 2 {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
