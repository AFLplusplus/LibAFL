use libafl::{executors::{InProcessExecutor, ExitKind}, inputs::Input, observers::ObserversTuple};


pub struct NyxInProcessExecutor<'a,H,I,OT, S>
where
    H: FnMut(&I) -> ExitKind, 
    I: Input,
    OT: ObserversTuple<I,S>
{
    base: InProcessExecutor<'a, H, I, OT, S>,
}

