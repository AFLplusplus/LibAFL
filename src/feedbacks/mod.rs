use crate::corpus::Testcase;
use crate::executors::Executor;

pub trait Feedback {

    fn is_interesting(&mut self, executor: &dyn Executor, entry: &dyn Testcase) -> f64;

}
