pub mod inmemory;

use crate::corpus::Testcase;
use core::cell::RefCell;
use std::rc::Rc;
use crate::corpus::Corpus;
use crate::corpus::TestcaseMetadata;
use crate::feedbacks::Feedback;
use crate::inputs::Input;
use crate::observers::Observer;
use crate::AflError;

pub enum ExitKind {
    Ok,
    Crash,
    OOM,
    Timeout,
}

// TODO unbox input

pub trait Executor<I, C>
where
    I: Input,
    C: Corpus<I>,
{
    /// Instruct the target about the input and run
    fn run_target(&mut self, input: &mut I) -> Result<ExitKind, AflError>;

    /// Reset the state of all the observes linked to this executor
    fn reset_observers(&mut self) -> Result<(), AflError>;

    /// Run the post exec hook for all the observes linked to this executor
    fn post_exec_observers(&mut self) -> Result<(), AflError>;

    /// Add a linked observer
    fn add_observer(&mut self, observer: Box<dyn Observer>);

    /// Get the linked observers
    fn observers(&self) -> &Vec<Box<dyn Observer>>;

    /// Adds a feedback
    fn add_feedback(&mut self, feedback: Box<dyn Feedback<I>>);

    /// Returns vector of feebacks
    fn feedbacks(&self) -> &Vec<Box<dyn Feedback<I>>>;

    // TODO: Move to another struct, like evaluator?
    // In any case, the dependency on Corpus should probably go
    /// Runs the input and triggers observers and feedback
    fn evaluate_input(
        &mut self,
        corpus: &mut C,
        input: &mut I,
    ) -> Result<bool, AflError> {
        self.reset_observers()?;
        self.run_target(input)?;
        self.post_exec_observers()?;

        let mut metadatas: Vec<Box<dyn TestcaseMetadata>> = vec![];
        let mut rate_acc = 0;
        for feedback in self.feedbacks() {
            let (rate, meta) = feedback.is_interesting(input);
            rate_acc += rate;
            if let Some(m) = meta {
                metadatas.push(m);
            }
        }

        if rate_acc >= 25 {
            let new_entry = Rc::new(RefCell::new(Testcase::<I>::new(input.clone())));
            for meta in metadatas {
                new_entry.borrow_mut().add_metadata(meta);
            }
            corpus.add(new_entry);

            Ok(true)
        } else {
            Ok(false)
        }
    }

}
