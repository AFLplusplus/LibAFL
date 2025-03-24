/// Rust bindings for Apple's [`pthread_introspection`](https://opensource.apple.com/source/libpthread/libpthread-218.20.1/pthread/introspection.h.auto.html) hooks.
use std::sync::RwLock;
const PTHREAD_INTROSPECTION_THREAD_CREATE: libc::c_uint = 1;
const PTHREAD_INTROSPECTION_THREAD_START: libc::c_uint = 2;
const PTHREAD_INTROSPECTION_THREAD_TERMINATE: libc::c_uint = 3;
const PTHREAD_INTROSPECTION_THREAD_DESTROY: libc::c_uint = 4;

#[expect(non_camel_case_types)]
type pthread_introspection_hook_t = extern "C" fn(
    event: libc::c_uint,
    thread: libc::pthread_t,
    addr: *const libc::c_void,
    size: libc::size_t,
);

unsafe extern "C" {
    fn pthread_introspection_hook_install(
        hook: *const pthread_introspection_hook_t,
    ) -> *const pthread_introspection_hook_t;
}

struct PreviousHook(*const pthread_introspection_hook_t);

impl PreviousHook {
    /// Dispatch to the previous hook, if it is set.
    pub unsafe fn dispatch(
        &self,
        event: libc::c_uint,
        thread: libc::pthread_t,
        addr: *const libc::c_void,
        size: libc::size_t,
    ) {
        let inner = self.0;
        if inner.is_null() {
            return;
        }
        unsafe { (*inner)(event, thread, addr, size) };
    }

    /// Set the previous hook.
    pub fn set(&mut self, hook: *const pthread_introspection_hook_t) {
        self.0 = hook;
    }

    /// Ensure the previous hook is installed again.
    pub fn reset(&mut self) {
        let inner = self.0;
        if inner.is_null() {
            unsafe {
                pthread_introspection_hook_install(core::ptr::null());
            }
            return;
        }
        unsafe {
            self.0 = core::ptr::null();
            pthread_introspection_hook_install(inner);
        }
    }
}

// At the time where the inner is called, it will have been set.
// Mark it as sync.
unsafe impl Sync for PreviousHook {}

// TODO: This could use a RwLock as well
/// The previous hook
static mut PREVIOUS_HOOK: PreviousHook = PreviousHook(core::ptr::null());

/// The currently set hook
static CURRENT_HOOK: RwLock<Option<PthreadIntrospectionHook>> = RwLock::new(None);

/// Get the pointer to the previous hook, mut
fn previous_hook_ptr_mut() -> *mut PreviousHook {
    &raw mut PREVIOUS_HOOK
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
    unsafe { (*previous_hook_ptr_mut()).dispatch(event, thread, addr, size) };
}

/// Closure type for `pthread_introspection` hooks.
pub type PthreadIntrospectionHook =
    Box<dyn Fn(EventType, libc::pthread_t, *const libc::c_void, libc::size_t) + Sync + Send>;

/// Event type describing the lifecycle of a pthread.
#[derive(Debug, PartialEq, Eq)]
pub enum EventType {
    /// `pthread` creation
    Create,
    /// `pthread` starts
    Start,
    /// `pthread` terminates
    Terminate,
    /// `pthread` is being destroyed
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

impl From<EventType> for libc::c_uint {
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
/// # use libafl_frida::pthread_hook;
/// # use std::time::Duration;
/// # use std::thread;
/// unsafe {
///     pthread_hook::install(|event, pthread, addr, size| {
///         log::trace!(
///             "thread id=0x{:x} event={:?} addr={:?} size={:x}",
///             pthread,
///             event,
///             addr,
///             size
///         );
///     });
/// };
/// # thread::spawn(|| {
/// #     thread::sleep(Duration::from_millis(1));
/// # });
/// # thread::sleep(Duration::from_millis(50));
/// ```
/// This should output the thread IDs, lifecycle events, addresses and sizes of the corresponding events.
/// ```no_test
/// thread id=0x16bf67000 event=Create addr=0x16bf67000 size=4000
/// thread id=0x16bf67000 event=Start addr=0x16bd60000 size=208000
/// thread id=0x16bf67000 event=Terminate addr=0x16bd60000 size=208000
/// thread id=0x16bf67000 event=Destroy addr=0x16bf67000 size=4000
/// ```
///
/// # Safety
/// Potential data race when if called at the same time as `install` or `reset` from another thread
pub unsafe fn install<H>(hook: H)
where
    H: Fn(EventType, libc::pthread_t, *const libc::c_void, libc::size_t) + Send + Sync + 'static,
{
    let mut new_hook = CURRENT_HOOK.write().unwrap();
    *new_hook = Some(Box::new(hook));

    let prev = unsafe { pthread_introspection_hook_install(pthread_introspection_hook as _) };

    // Allow because we're sure this isn't from a different code generation unit.
    if !(prev).is_null() && !core::ptr::eq(prev, pthread_introspection_hook as _) {
        unsafe {
            (*previous_hook_ptr_mut()).set(prev as *const pthread_introspection_hook_t);
        }
    }
}

/// Restore a previously set `pthread_introspection` hook.
/// # Example
/// ```
/// # use libafl_frida::pthread_hook;
/// # use std::time::Duration;
/// # use std::thread;
/// unsafe { pthread_hook::reset() };
/// ```
///
/// # Safety
/// Potential data race when if called at the same time as `install` or `reset` from another thread
pub unsafe fn reset() {
    unsafe {
        (*previous_hook_ptr_mut()).reset();
    };
}

/// The following tests fail if they are not run sequentially.
#[cfg(test)]
mod test {
    use alloc::sync::Arc;
    use core::time::Duration;
    use std::{sync::Mutex, thread};

    use serial_test::serial;

    #[test]
    #[serial]
    fn test_nohook_thread_create() {
        let triggered: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

        thread::spawn(|| {
            thread::sleep(Duration::from_millis(1));
        });
        thread::sleep(Duration::from_millis(50));

        unsafe { super::reset() };
        assert!(!*triggered.lock().unwrap());
    }

    #[test]
    #[serial]
    fn test_hook_thread_create() {
        let triggered: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

        let inner_triggered = triggered.clone();
        unsafe {
            super::install(move |event, _, _, _| {
                if event == super::EventType::Create {
                    let mut triggered = inner_triggered.lock().unwrap();
                    *triggered = true;
                }
            });
        };

        thread::spawn(|| {
            thread::sleep(Duration::from_millis(1));
        });
        thread::sleep(Duration::from_millis(50));

        unsafe { super::reset() };
        assert!(*triggered.lock().unwrap());
    }

    #[test]
    #[serial]
    fn test_hook_thread_start() {
        let triggered: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

        let inner_triggered = triggered.clone();
        unsafe {
            super::install(move |event, _, _, _| {
                if event == super::EventType::Start {
                    let mut triggered = inner_triggered.lock().unwrap();
                    *triggered = true;
                }
            });
        };

        thread::spawn(|| {
            thread::sleep(Duration::from_millis(1));
        });
        thread::sleep(Duration::from_millis(50));

        unsafe { super::reset() };
        assert!(*triggered.lock().unwrap());
    }

    #[test]
    #[serial]
    fn test_hook_reset() {
        let triggered: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

        let inner_triggered = triggered.clone();
        unsafe {
            super::install(move |event, _, _, _| {
                if event == super::EventType::Start {
                    let mut triggered = inner_triggered.lock().unwrap();
                    *triggered = true;
                }
            });
        };

        unsafe { super::reset() };

        thread::spawn(|| {
            thread::sleep(Duration::from_millis(1));
        });
        thread::sleep(Duration::from_millis(50));

        assert!(!*triggered.lock().unwrap());
    }
}
