use alloc::rc::Rc;
use core::{cell::RefCell, fmt::Debug};

use libafl::{
    alloc, bolts::tuples::Named, events::EventFirer, executors::ExitKind, feedbacks::Feedback,
    inputs::UsesInput, observers::ObserversTuple, state::HasClientPerfMonitor, Error,
};

#[derive(Debug)]
pub struct LibfuzzerKeepFeedback {
    keep: Rc<RefCell<bool>>,
}

impl LibfuzzerKeepFeedback {
    pub fn new() -> Self {
        Self {
            keep: Rc::new(RefCell::new(false)),
        }
    }

    pub fn keep(&self) -> Rc<RefCell<bool>> {
        self.keep.clone()
    }
}

impl Named for LibfuzzerKeepFeedback {
    fn name(&self) -> &str {
        "libfuzzer-keep"
    }
}

impl<S> Feedback<S> for LibfuzzerKeepFeedback
where
    S: UsesInput + HasClientPerfMonitor,
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
        Ok(*self.keep.borrow())
    }
}
