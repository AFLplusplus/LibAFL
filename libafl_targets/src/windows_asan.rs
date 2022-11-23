//! Setup asan death callbback

use libafl::{
    events::{EventFirer, EventRestarter},
    executors::{inprocess::windows_asan_handler::asan_death_handler, Executor, HasObservers},
    feedbacks::Feedback,
    state::{HasClientPerfMonitor, HasSolutions},
    HasObjective,
};

/// Asan death callback type
pub type CB = unsafe extern "C" fn() -> ();

extern "C" {
    fn __sanitizer_set_death_callback(cb: CB);
}

/// # Safety
/// Setup asan callback on windows
// See https://github.com/AFLplusplus/LibAFL/issues/769
// This is needed to intercept asan error exit
// When we use AddressSanitizer on windows, the crash handler is not called when ASAN detects an error
// This is because, on linux, ASAN runtime raises SIGABRT so we can rely on the signal handler
// but on windows it simply calls TerminateProcess.
// so we need to call the api by asan to register the callback when asan is about to finish the process.
pub unsafe fn setup_asan_callback<E, EM, OF, Z>(_executor: &E, _event_mgr: &EM, _fuzzer: &Z)
where
    E: Executor<EM, Z> + HasObservers,
    EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
    OF: Feedback<E::State>,
    E::State: HasSolutions + HasClientPerfMonitor,
    Z: HasObjective<Objective = OF, State = E::State>,
{
    __sanitizer_set_death_callback(asan_death_handler::<E, EM, OF, Z>);
}
