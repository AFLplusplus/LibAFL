pub mod inmemory;

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::corpus::Testcase;
use crate::feedbacks::Feedback;
use crate::inputs::Input;
use crate::observers::Observer;
use crate::AflError;
use alloc::rc::Rc;
use core::cell::RefCell;

pub enum ExitKind {
    Ok,
    Crash,
    OOM,
    Timeout,
}

// TODO unbox input

pub trait Executor<I>
where
    I: Input,
{
    /// Instruct the target about the input and run
    fn run_target(&mut self, input: &I) -> Result<ExitKind, AflError>;

    /// Reset the state of all the observes linked to this executor
    fn reset_observers(&mut self) -> Result<(), AflError>;

    /// Run the post exec hook for all the observes linked to this executor
    fn post_exec_observers(&mut self) -> Result<(), AflError>;

    /// Add a linked observer
    fn add_observer(&mut self, observer: Box<dyn Observer>);

    /// Get the linked observers
    fn observers(&self) -> &[Box<dyn Observer>];

    /// Adds a feedback
    fn add_feedback(&mut self, feedback: Box<dyn Feedback<I>>);

    /// Returns vector of feebacks
    fn feedbacks(&self) -> &[Box<dyn Feedback<I>>];

    /// Returns vector of feebacks (mutable)
    fn feedbacks_mut(&mut self) -> &mut Vec<Box<dyn Feedback<I>>>;

    /// Runs the input and triggers observers and feedback
    // TODO: Move to another struct, like evaluator?
    fn evaluate_input(&mut self, input: &I) -> Result<bool, AflError> {
        self.reset_observers()?;
        self.run_target(input)?;
        self.post_exec_observers()?;

        let mut rate_acc = 0;
        for feedback in self.feedbacks_mut() {
            rate_acc += feedback.is_interesting(input)?;
        }

        if rate_acc >= 25 {
            let testcase = Rc::new(RefCell::new(Testcase::new(input.clone())));
            for feedback in self.feedbacks_mut() {
                feedback.append_metadata(testcase.clone())?;
            }
            Ok(true)
        } else {
            for feedback in self.feedbacks_mut() {
                feedback.discard_metadata()?;
            }
            Ok(false)
        }
    }
}
