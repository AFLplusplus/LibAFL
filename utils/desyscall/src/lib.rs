use libc::{c_int, c_void};
use meminterval::IntervalTree;
use std::{mem::MaybeUninit, sync::Once};

pub mod file;
pub mod mmap;

pub type Pointer = *mut c_void;

#[derive(Debug, Clone)]
pub struct Mapping {
    prot: c_int,
    flags: c_int,
    mapped: bool,
}

pub struct Context {
    enabled: bool,
    mappings: IntervalTree<Pointer, Mapping>,
    exit_hook: Option<Box<dyn FnMut(i32)>>,
}

impl Context {
    pub fn new() -> Self {
        Self {
            enabled: false,
            mappings: IntervalTree::new(),
            exit_hook: None,
        }
    }

    pub fn disable(&mut self) -> bool {
        let prev = self.enabled;
        self.enabled = false;
        prev
    }

    pub fn enable(&mut self) -> bool {
        let prev = self.enabled;
        self.enabled = true;
        prev
    }

    pub fn print_mappings(&self) {
        for entry in self.mappings.query((0 as Pointer)..(usize::MAX as Pointer)) {
            println!(
                "{:?}-{:?}\t==> {:?}",
                entry.interval.start, entry.interval.end, entry.value
            );
        }
    }

    pub fn register_exit_hook(&mut self, hook: Box<dyn FnMut(i32)>) {
        self.exit_hook = Some(hook);
    }

    pub fn get() -> &'static mut Context {
        // TODO use Mutex with a feature
        static mut SINGLETON_CONTEXT: MaybeUninit<Context> = MaybeUninit::uninit();
        static ONCE: Once = Once::new();
        unsafe {
            ONCE.call_once(|| {
                SINGLETON_CONTEXT.write(Context::new());
            });

            SINGLETON_CONTEXT.assume_init_mut()
        }
    }
}

extern "C" {
    fn __libafl_raw_exit_group(status: c_int);
}

// void _exit(int status);
#[no_mangle]
pub unsafe fn _exit(status: c_int) {
    let ctx = Context::get();

    if ctx.enabled {
        if let Some(hook) = &mut ctx.exit_hook {
            (hook)(status as i32);
        }
    }

    __libafl_raw_exit_group(status);
}
