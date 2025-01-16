//! Setup asan death callbback

use libafl::{
    corpus::Corpus,
    events::{EventFirer, EventRestarter},
    executors::{hooks::windows::windows_asan_handler::asan_death_handler, Executor, HasObservers},
    feedbacks::Feedback,
    inputs::Input,
    observers::ObserversTuple,
    state::{HasCorpus, HasCurrentTestcase, HasExecutions, HasSolutions},
    HasObjective,
};

/// Asan death callback type
pub type CB = unsafe extern "C" fn() -> ();

extern "C" {
    fn __sanitizer_set_death_callback(cb: Option<CB>);
}

/// Setup `ASan` callback on windows
///
/// This is needed to intercept `ASan` error exit.
///
/// When we use `AddressSanitizer` on Windows, the crash handler is not called when `ASan` detects an error
/// This is because, on linux, `ASan` runtime raises `SIGABRT` so we can rely on the signal handler
/// but on Windows it simply calls `TerminateProcess`.
/// so we need to call the API by `ASan` to register the callback when `ASan` is about to finish the process.
/// See <https://github.com/AFLplusplus/LibAFL/issues/769>.
///
/// # Safety
/// Calls the unsafe `__sanitizer_set_death_callback` symbol, but should be safe to call otherwise.
pub unsafe fn setup_asan_callback<E, EM, I, OF, S, Z>(_executor: &E, _event_mgr: &EM, _fuzzer: &Z)
where
    E: Executor<EM, I, S, Z> + HasObservers,
    E::Observers: ObserversTuple<I, S>,
    EM: EventFirer<I, S> + EventRestarter<S>,
    OF: Feedback<EM, I, E::Observers, S>,
    S: HasExecutions + HasSolutions<I> + HasCurrentTestcase<I> + HasCorpus<I>,
    Z: HasObjective<Objective = OF>,
    I: Input + Clone,
{
    __sanitizer_set_death_callback(Some(asan_death_handler::<E, EM, I, OF, S, Z>));
}
