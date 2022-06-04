use ctor::ctor;
use libafl_targets::forkserver_init;
#[ctor]
fn init() {
    forkserver_init();
}
