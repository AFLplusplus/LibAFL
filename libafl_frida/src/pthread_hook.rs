/// Rust bindings for Apple's [`pthread_introspection`](https://opensource.apple.com/source/libpthread/libpthread-218.20.1/pthread/introspection.h.auto.html) hooks.
use lazy_static::lazy_static;
use libc;
use std::cell::UnsafeCell;
use std::convert::{TryFrom, TryInto};
use std::sync::RwLock;

const PTHREAD_INTROSPECTION_THREAD_CREATE: libc::c_uint = 1;
const PTHREAD_INTROSPECTION_THREAD_START: libc::c_uint = 2;
const PTHREAD_INTROSPECTION_THREAD_TERMINATE: libc::c_uint = 3;
const PTHREAD_INTROSPECTION_THREAD_DESTROY: libc::c_uint = 4;

#[allow(non_camel_case_types)]
type pthread_introspection_hook_t = extern "C" fn(
    event: libc::c_uint,
    thread: libc::pthread_t,
    addr: *const libc::c_void,
    size: libc::size_t,
);

extern "C" {
    fn pthread_introspection_hook_install(
        hook: *const libc::c_void,
    ) -> pthread_introspection_hook_t;
}

struct PreviousHook(UnsafeCell<Option<pthread_introspection_hook_t>>);

impl PreviousHook {
    /// Dispatch to the previous hook, if it is set.
    pub fn dispatch(
        &self,
        event: libc::c_uint,
        thread: libc::pthread_t,
        addr: *const libc::c_void,
        size: libc::size_t,
    ) {
        let inner = unsafe { *self.0.get() };
        if inner.is_none() {
            return;
        }
        let inner = inner.unwrap();
        inner(event, thread, addr, size);
    }

    /// Set the previous hook.
    pub fn set(&self, hook: pthread_introspection_hook_t) {
        unsafe {
            *self.0.get() = Some(hook);
        }
    }

    /// Ensure the previous hook is installed again.
    pub fn reset(&self) {
        let inner = unsafe { *self.0.get() };
        if inner.is_none() {
            unsafe {
                pthread_introspection_hook_install(std::ptr::null());
            }
            return;
        }
        let inner = inner.unwrap();
        unsafe {
            *self.0.get() = None;
            pthread_introspection_hook_install(inner as *const libc::c_void);
        }
    }
}

// At the time where the inner is called, it will have been set.
// Mark it as sync.
unsafe impl Sync for PreviousHook {}

#[allow(non_upper_case_globals)]
static PREVIOUS_HOOK: PreviousHook = PreviousHook(UnsafeCell::new(None));

lazy_static! {
    static ref CURRENT_HOOK: RwLock<Option<PthreadIntrospectionHook>> = RwLock::new(None);
}

extern "C" fn pthread_introspection_hook(
    event: libc::c_uint,
    thread: libc::pthread_t,
    addr: *const libc::c_void,
    size: libc::size_t,
) {
    if let Some(ref hook) = *CURRENT_HOOK.read().unwrap() {
        hook(event.try_into().unwrap(), thread, addr, size);
    }
    PREVIOUS_HOOK.dispatch(event, thread, addr, size);
}

/// Closure type for `pthread_introspection` hooks.
pub type PthreadIntrospectionHook =
    Box<dyn Fn(EventType, libc::pthread_t, *const libc::c_void, libc::size_t) + Sync + Send>;

/// Event type describing the lifecycle of a pthread.
#[derive(Debug, PartialEq, Eq)]
pub enum EventType {
    Create,
    Start,
    Terminate,
    Destroy,
}

impl TryFrom<libc::c_uint> for EventType {
    type Error = ();

    fn try_from(value: libc::c_uint) -> Result<Self, Self::Error> {
        match value {
            PTHREAD_INTROSPECTION_THREAD_CREATE => Ok(Self::Create),
            PTHREAD_INTROSPECTION_THREAD_START => Ok(Self::Start),
            PTHREAD_INTROSPECTION_THREAD_TERMINATE => Ok(Self::Terminate),
            PTHREAD_INTROSPECTION_THREAD_DESTROY => Ok(Self::Destroy),
            _ => Err(()),
        }
    }
}

impl std::convert::From<EventType> for libc::c_uint {
    fn from(event: EventType) -> Self {
        match event {
            EventType::Create => PTHREAD_INTROSPECTION_THREAD_CREATE,
            EventType::Start => PTHREAD_INTROSPECTION_THREAD_START,
            EventType::Terminate => PTHREAD_INTROSPECTION_THREAD_TERMINATE,
            EventType::Destroy => PTHREAD_INTROSPECTION_THREAD_DESTROY,
        }
    }
}

/// Set a `pthread_introspection` hook.
/// # Example
/// ```
///# use libafl_frida::pthread_hook;
///# use std::time::Duration;
///# use std::thread;
/// pthread_hook::install(|event, pthread, addr, size| {
///     println!("thread id=0x{:x} event={:?} addr={:?} size={:x}", pthread, event, addr, size);
/// });
///# thread::spawn(|| {
///#     thread::sleep(Duration::from_millis(1));
///# });
///# thread::sleep(Duration::from_millis(50));
/// ```
/// This should output the thread IDs, lifecycle events, addresses and sizes of the corresponding events.
/// ```no_test
/// thread id=0x16bf67000 event=Create addr=0x16bf67000 size=4000
/// thread id=0x16bf67000 event=Start addr=0x16bd60000 size=208000
/// thread id=0x16bf67000 event=Terminate addr=0x16bd60000 size=208000
/// thread id=0x16bf67000 event=Destroy addr=0x16bf67000 size=4000
/// ```
pub fn install<H>(hook: H)
where
    H: Fn(EventType, libc::pthread_t, *const libc::c_void, libc::size_t) + Send + Sync + 'static,
{
    let mut new_hook = CURRENT_HOOK.write().unwrap();
    *new_hook = Some(Box::new(hook));

    let prev = unsafe {
        pthread_introspection_hook_install(pthread_introspection_hook as *const libc::c_void)
    };

    // Allow because we're sure this isn't from a different code generation unit.
    #[allow(clippy::fn_address_comparisons)]
    if !(prev as *const libc::c_void).is_null() && prev != pthread_introspection_hook {
        PREVIOUS_HOOK.set(prev);
    }
}

/// Restore a previously set `pthread_introspection` hook.
/// # Example
/// ```
///# use libafl_frida::pthread_hook;
///# use std::time::Duration;
///# use std::thread;
/// pthread_hook::reset();
/// ```
pub fn reset() {
    PREVIOUS_HOOK.reset();
}

/// The following tests fail if they are not run sequentially.
#[cfg(test)]
mod test {
    use serial_test::serial;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    #[test]
    #[serial]
    fn test_nohook_thread_create() {
        let triggered: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

        thread::spawn(|| {
            thread::sleep(Duration::from_millis(1));
        });
        thread::sleep(Duration::from_millis(50));

        super::reset();
        assert!(*triggered.lock().unwrap() == false);
    }

    #[test]
    #[serial]
    fn test_hook_thread_create() {
        let triggered: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

        let inner_triggered = triggered.clone();
        super::install(move |event, _, _, _| {
            if event == super::EventType::Create {
                let mut triggered = inner_triggered.lock().unwrap();
                *triggered = true;
            }
        });

        thread::spawn(|| {
            thread::sleep(Duration::from_millis(1));
        });
        thread::sleep(Duration::from_millis(50));

        super::reset();
        assert!(*triggered.lock().unwrap() == true);
    }

    #[test]
    #[serial]
    fn test_hook_thread_start() {
        let triggered: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

        let inner_triggered = triggered.clone();
        super::install(move |event, _, _, _| {
            if event == super::EventType::Start {
                let mut triggered = inner_triggered.lock().unwrap();
                *triggered = true;
            }
        });

        thread::spawn(|| {
            thread::sleep(Duration::from_millis(1));
        });
        thread::sleep(Duration::from_millis(50));

        super::reset();
        assert!(*triggered.lock().unwrap() == true);
    }

    #[test]
    #[serial]
    fn test_hook_reset() {
        let triggered: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

        let inner_triggered = triggered.clone();
        super::install(move |event, _, _, _| {
            if event == super::EventType::Start {
                let mut triggered = inner_triggered.lock().unwrap();
                *triggered = true;
            }
        });

        super::reset();

        thread::spawn(|| {
            thread::sleep(Duration::from_millis(1));
        });
        thread::sleep(Duration::from_millis(50));

        assert!(*triggered.lock().unwrap() == false);
    }
}
