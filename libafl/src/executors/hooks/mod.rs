/// Hooks for inprocess fork executors
#[cfg(all(unix, feature = "std"))]
pub mod inprocess_fork_hooks_unix;
/// The essential hooks for inproc executors
/// hooks are the code that are run before and after each executor run
#[cfg(unix)]
pub mod inprocess_hooks_unix;

/// Hooks for setting/resetting timeouts
#[cfg(feature = "std")]
pub mod timeout_hooks_unix;

/// The hooks that runs before and after running the target
pub trait ExecutorHooks {
    /// The pre_exec hook that is called before running a target.
    #[allow(clippy::unused_self)]
    fn pre_run_target<E, EM, I, S, Z>(
        &self,
        _executor: &E,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    );

    /// The post_exec hooks that runs before and after running the target
    fn post_run_target(&self);
}
