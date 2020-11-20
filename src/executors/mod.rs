pub mod inmemory;

use crate::inputs::Input;
use crate::AflError;

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
}
