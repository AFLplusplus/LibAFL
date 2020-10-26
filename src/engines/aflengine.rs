use std::time;

use crate::utils::Rand;
use crate::feedbacks::Feedback;
use crate::stages::Stage;
use crate::executors::Executor;
use crate::engines::Engine;
use crate::monitors::Monitor;

pub struct AflEngine<'a> {

    pub rand: &'a mut dyn Rand,
    pub feedbacks: Vec<Box<dyn Feedback>>,

    pub stages: Vec<Box<dyn Stage>>,
    pub current_stage: &'a Box<dyn Stage>,

    pub executor: Box<dyn Executor>,

    pub executions: u64,

    pub time_start: time::SystemTime,
    pub time_last_find: Option<time::SystemTime>,

    // TODO: Map
    pub monitors: Vec<Box<dyn Monitor>>,

}

impl Engine<'_> for AflEngine<'_> {

}