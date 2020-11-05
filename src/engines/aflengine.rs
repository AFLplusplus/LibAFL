use std::time;

use crate::engines::Evaluator;
use crate::executors::Executor;
use crate::feedbacks::Feedback;
use crate::inputs::Input;
use crate::monitors::Monitor;
use crate::stages::Stage;
use crate::utils::Rand;

/*
pub struct AflEngine<'a, I: Input> {
    pub rand: &'a mut dyn Rand,
    pub feedbacks: Vec<Box<dyn Feedback<I>>>,

    pub stages: Vec<Box<dyn Stage<I>>>,
    pub current_stage: &'a Box<dyn Stage<I>>,

    pub executor: Box<dyn Executor<dyn Input>>,

    pub executions: u64,

    pub time_start: time::SystemTime,
    pub time_last_find: Option<time::SystemTime>,

    // TODO: Map
    pub monitors: Vec<Box<dyn Monitor>>,
}

impl<I: Input> Engine<'_> for AflEngine<'_, I> {}
*/
