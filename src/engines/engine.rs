use std::time;

pub trait RandState {}
pub trait Executor {}
pub trait Feedback {}
pub trait Stage {}

pub trait Monitor {}

pub struct DefaultEngine {

    pub rand: Box<dyn RandState>,
    pub feedback: Vec<Box<dyn Feedback>>,

    pub stages: Vec<Box<dyn Stage>>,
    pub current_stage: Box<dyn Stage>,

    pub executor: Box<dyn Executor>,

    pub executions: u64,

    pub time_start: time::SystemTime,
    pub time_last_find: Option<time::SystemTime>,

    // TODO: Map
    pub monitors: Vec<Box<dyn Monitor>>,

}