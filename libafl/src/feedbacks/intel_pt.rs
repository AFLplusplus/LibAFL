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
    avg_score: f64,
}

impl IntelPTFeedback {
    pub fn new(trace: Arc<Mutex<Vec<u8>>>) -> Self {
        Self {
            trace,
            past_traces: vec![],
            avg_score: 0.0,
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
        let trace = self.trace.lock().unwrap();
        if self.past_traces.is_empty() {
            self.past_traces.push(trace.clone());
            return Ok(true);
        }

        let mut tot_score = 0;
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
            tot_score += score;
        }

        let weighted_score = tot_score as f64 / self.past_traces.len() as f64;

        self.past_traces.push(trace.clone());
        let n = self.past_traces.len() as f64;
        self.avg_score = (self.avg_score * (n - 1.0) + weighted_score) / n;

        if n > 200.0 && weighted_score > self.avg_score * 2.0 {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
