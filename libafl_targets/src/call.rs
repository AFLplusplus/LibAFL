use core::marker::PhantomData;

use hashbrown::HashMap;
use libafl::{
    executors::{hooks::ExecutorHook, HasObservers},
    inputs::UsesInput,
};
use once_cell::sync::Lazy;
/// The list of functions that this execution has observed
pub static mut FUNCTION_LIST: Lazy<HashMap<usize, usize>> = Lazy::new(HashMap::new);

#[no_mangle]
/// The runtime code inserted at every callinst invokation (if you used the function-logging.cc)
/// # Safety
/// unsafe because it touches the pub static mut `FUNCTION_LIST`.
/// May not be called concurrently.
pub unsafe extern "C" fn __libafl_target_call_hook(id: usize) {
    let function_list_ptr = &raw mut FUNCTION_LIST;
    let function_list = &mut *function_list_ptr;
    *function_list.entry(id).or_insert(0) += 1;
}

/// The empty struct to clear the `FUNCTION_LIST` before the execution
#[derive(Debug, Clone, Copy, Default)]
pub struct CallHook<S> {
    phantom: PhantomData<S>,
}

impl<S> CallHook<S> {
    /// The constructor
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<S> ExecutorHook<S> for CallHook<S>
where
    S: UsesInput,
{
    fn init<E: HasObservers>(&mut self, _state: &mut S) {}

    fn pre_exec(&mut self, _state: &mut S, _input: &<S as UsesInput>::Input) {
        // clear it before the execution
        // # Safety
        // This typically happens while no other execution happens.
        // In theory there is a race, but we can ignore it _for this use case_.
        unsafe {
            let function_list_ptr = &raw mut FUNCTION_LIST;
            let function_list = &mut *function_list_ptr;
            function_list.clear();
        }
    }

    fn post_exec(&mut self, _state: &mut S, _input: &<S as UsesInput>::Input) {}
}
