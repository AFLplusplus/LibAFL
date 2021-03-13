pub mod map;
pub use map::*;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::time::Duration;
use serde::{Deserialize, Serialize};
use std::os::raw::c_int;
use std::ptr::null_mut;

use crate::{
    bolts::tuples::{MatchFirstType, MatchNameAndType, MatchType, Named, TupleList},
    utils::current_time,
    Error,
};

/// Observers observe different information about the target.
/// They can then be used by various sorts of feedback.
pub trait Observer: Named + serde::Serialize + serde::de::DeserializeOwned + 'static {
    /// The testcase finished execution, calculate any changes.
    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }

    /// Resets the observer
    fn pre_exec(&mut self) -> Result<(), Error>;

    /// This function is executed after each fuzz run
    #[inline]
    fn post_exec(&mut self) -> Result<(), Error> {
        Ok(())
    }

    /// Serialize this observer's state only, to be restored later using deserialize_state
    /// As opposed to completely serializing the observer, this is only needed when the fuzzer is to be restarted
    /// If no state is needed to be kept, just return an empty vec.
    /// Example:
    /// >> The virgin_bits map in AFL needs to be in sync with the corpus
    #[inline]
    fn serialize_state(&mut self) -> Result<Vec<u8>, Error> {
        Ok(vec![])
    }

    /// Restore the state from a given vec, priviously stored using `serialize_state`
    #[inline]
    fn deserialize_state(&mut self, serialized_state: &[u8]) -> Result<(), Error> {
        let _ = serialized_state;
        Ok(())
    }
}

/// A hastkel-style tuple of observers
pub trait ObserversTuple:
    MatchNameAndType + MatchType + MatchFirstType + serde::Serialize + serde::de::DeserializeOwned
{
    /// Reset all executors in the tuple
    /// This is called right before the next execution.
    fn pre_exec_all(&mut self) -> Result<(), Error>;

    /// Do whatever you need to do after a run.
    /// This is called right after the last execution
    fn post_exec_all(&mut self) -> Result<(), Error>;
}

impl ObserversTuple for () {
    fn pre_exec_all(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn post_exec_all(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

impl<Head, Tail> ObserversTuple for (Head, Tail)
where
    Head: Observer,
    Tail: ObserversTuple + TupleList,
{
    fn pre_exec_all(&mut self) -> Result<(), Error> {
        self.0.pre_exec()?;
        self.1.pre_exec_all()
    }

    fn post_exec_all(&mut self) -> Result<(), Error> {
        self.0.post_exec()?;
        self.1.post_exec_all()
    }
}

/// A simple observer, just overlooking the runtime of the target.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TimeObserver {
    name: String,
    start_time: Duration,
    last_runtime: Option<Duration>,
    exec_tmout: Option<Duration>,
}

#[repr(C)]
struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[repr(C)]
struct Itimerval {
    pub it_interval: Timeval,
    pub it_value: Timeval,
}

extern "C" {
    fn setitimer(which: c_int, new_value: *mut Itimerval, old_value: *mut Itimerval) -> c_int;
}

const ITIMER_REAL: c_int = 0;

impl TimeObserver {
    /// Creates a new TimeObserver with the given name.
    pub fn new(name: &'static str) -> Self {
        Self {
            name: name.to_string(),
            start_time: Duration::from_secs(0),
            last_runtime: None,
            exec_tmout: None,
        }
    }

    pub fn last_runtime(&self) -> &Option<Duration> {
        &self.last_runtime
    }
}

impl Observer for TimeObserver {
    fn pre_exec(&mut self) -> Result<(), Error> {

        #[cfg(unix)]
        match self.exec_tmout {
            Some(exec_tmout) => unsafe {
                let milli_sec = exec_tmout.as_millis() as i64;
                let it_value = Timeval{
                    tv_sec: milli_sec / 1000,
                    tv_usec: milli_sec % 1000,
                };
                let it_interval = Timeval{
                    tv_sec: 0,
                    tv_usec: 0,
                };
                setitimer(
                    ITIMER_REAL,
                    &mut Itimerval{
                        it_interval,
                        it_value,
                    },
                    null_mut(),
                );
            },
            None => (),
        }

        self.last_runtime = None;
        self.start_time = current_time();
        Ok(())
    }

    fn post_exec(&mut self) -> Result<(), Error> {
        self.last_runtime = Some(current_time() - self.start_time);

        #[cfg(unix)]
        match self.exec_tmout {
            Some(_) => unsafe {
                let it_value = Timeval{
                    tv_sec: 0,
                    tv_usec: 0,
                };
                let it_interval = Timeval{
                    tv_sec: 0,
                    tv_usec: 0,
                };
                setitimer(
                    ITIMER_REAL,
                    &mut Itimerval{
                        it_interval,
                        it_value,
                    },
                    null_mut(),
                );
            },
            None => (),
        }

        Ok(())
    }
}

impl Named for TimeObserver {
    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {

    use crate::{
        bolts::tuples::{tuple_list, tuple_list_type, Named},
        observers::{StdMapObserver, TimeObserver},
    };

    static mut MAP: [u32; 4] = [0; 4];

    #[test]
    fn test_observer_serde() {
        let obv = tuple_list!(
            TimeObserver::new("time"),
            StdMapObserver::new("map", unsafe { &mut MAP })
        );
        let vec = postcard::to_allocvec(&obv).unwrap();
        println!("{:?}", vec);
        let obv2: tuple_list_type!(TimeObserver, StdMapObserver<u32>) =
            postcard::from_bytes(&vec).unwrap();
        assert_eq!(obv.0.name(), obv2.0.name());
    }
}
