use libafl_targets::forkserver_init;
use ctor::ctor;
#[ctor]
fn init() {
    forkserver_init();
}