use core::marker::PhantomData;
use std::sync::{LazyLock, Mutex};

use hashbrown::HashMap;
use libafl::executors::hooks::ExecutorHook;

/// The list of functions that this execution has observed, synchronized across threads.
pub static FUNCTION_LIST: LazyLock<Mutex<HashMap<usize, usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[unsafe(no_mangle)]
/// The runtime code inserted at every callinst invocation (if you used `function-logging.cc`).
///
/// # Safety
/// Safe to call from C call-logging instrumentation hooks.
pub unsafe extern "C" fn __libafl_target_call_hook(id: usize) {
    let guard = match FUNCTION_LIST.try_lock() {
        Ok(guard) => Some(guard),
        Err(std::sync::TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
        Err(std::sync::TryLockError::WouldBlock) => None,
    };
    if let Some(mut list) = guard {
        let count = list.entry(id).or_insert(0);
        *count = count.saturating_add(1);
    }
}

/// The empty struct to clear the `FUNCTION_LIST` before the execution
#[derive(Debug, Copy, Clone, Default)]
pub struct CallHook<I, S> {
    phantom: PhantomData<(I, S)>,
}

impl<I, S> CallHook<I, S> {
    /// The constructor
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<I, S> ExecutorHook<I, S> for CallHook<I, S> {
    fn init(&mut self, _state: &mut S) {}

    fn pre_exec(&mut self, _state: &mut S, _input: &I) {
        FUNCTION_LIST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    fn post_exec(&mut self, _state: &mut S, _input: &I) {}
}

#[cfg(test)]
mod tests {
    use std::thread;

    use libafl::executors::hooks::ExecutorHook;

    use super::{__libafl_target_call_hook, CallHook, FUNCTION_LIST};

    #[test]
    fn test_call_hook_concurrent_access() {
        let mut hook = CallHook::<(), ()>::new();
        hook.pre_exec(&mut (), &());

        thread::scope(|s| {
            for t in 0..4usize {
                s.spawn(move || {
                    for i in 0..64usize {
                        unsafe {
                            __libafl_target_call_hook((t << 8) | i);
                        }
                    }
                });
            }
            s.spawn(|| {
                let mut h = CallHook::<(), ()>::new();
                for _ in 0..8 {
                    h.pre_exec(&mut (), &());
                }
            });
        });

        unsafe {
            __libafl_target_call_hook(0xDEAD_BEEF);
        }
        assert!(!FUNCTION_LIST.lock().unwrap().is_empty());
        hook.pre_exec(&mut (), &());
        assert!(FUNCTION_LIST.lock().unwrap().is_empty());
    }
}
