use ctor::{ctor, dtor};
use std::env;

struct State {}

impl State {
    fn new() -> Self {
        Self {}
    }
}

static mut GLOBAL_DATA: Option<State> = None;

#[ctor]
fn init() {
    unsafe { GLOBAL_DATA = Some(State::new()) }
}
#[dtor]
fn fini() {
    // drops the global data object
    unsafe { GLOBAL_DATA = None }
}

fn with_state<R>(cb: impl FnOnce(&mut State) -> R) -> R {
    use unchecked_unwrap::UncheckedUnwrap;
    let s = unsafe { GLOBAL_DATA.as_mut().unchecked_unwrap() };
    cb(s)
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn _sym_push_path_constraint(
    constraint: *const std::ffi::c_void,
    taken: bool,
    site_id: usize,
) {
    with_state(|s| {
        println!("just testing {}", site_id + 3);
    })
}
