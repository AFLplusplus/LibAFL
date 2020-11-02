use std::time;

use crate::engines::Engine;
use crate::inputs::Input;
use crate::executors::Executor;
use crate::feedbacks::Feedback;
use crate::monitors::Monitor;
use crate::stages::Stage;
use crate::utils::Rand;

pub struct AflEngine<'a, InputT: Input> {
    pub rand: &'a mut dyn Rand,
    pub feedbacks: Vec<Box<dyn Feedback<InputT>>>,

    pub stages: Vec<Box<dyn Stage<InputT>>>,
    pub current_stage: &'a Box<dyn Stage<InputT>>,

    pub executor: Box<dyn Executor>,

    pub executions: u64,

    pub time_start: time::SystemTime,
    pub time_last_find: Option<time::SystemTime>,

    // TODO: Map
    pub monitors: Vec<Box<dyn Monitor>>,
}

impl<InputT: Input> Engine<'_> for AflEngine<'_, InputT> {}
