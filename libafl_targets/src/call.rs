use core::marker::PhantomData;

use hashbrown::HashMap;
use libafl::{
    executors::{hooks::ExecutorHook, HasObservers},
    inputs::UsesInput,
};
use once_cell::sync::Lazy;
/// The list of functions that this execution has observed
pub static mut FUNCTION_LIST: Lazy<HashMap<usize, usize>> = Lazy::new(|| {
    let m = HashMap::new();
    m
});

#[no_mangle]
/// The runtime code inserted at every callinst invokation (if you used the function-logging.cc)
pub unsafe extern "C" fn __libafl_target_call_hook(id: usize) {
    *FUNCTION_LIST.entry(id).or_insert(0) += 1;
}

/// The empty struct to clear the FUNCTION_LIST before the execution
#[derive(Debug, Clone, Copy)]
pub struct CallHook<S> {
    phantom: PhantomData<S>,
}

impl<S> ExecutorHook<S> for CallHook<S>
where
    S: UsesInput,
{
    fn init<E: HasObservers>(&mut self, _state: &mut S) {}

    fn pre_exec(&mut self, _state: &mut S, _input: &<S as UsesInput>::Input) {
        // clear it before the execution
        unsafe { FUNCTION_LIST.clear() }
    }

    fn post_exec(&mut self, _state: &mut S, _input: &<S as UsesInput>::Input) {}
}