extern crate num;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::time::Duration;
use serde::{Deserialize, Serialize};

use crate::{
    serde_anymap::{ArrayMut, Cptr},
    tuples::{MatchNameAndType, MatchType, Named, TupleList},
    utils::current_time,
    AflError,
};

/// Observers observe different information about the target.
/// They can then be used by various sorts of feedback.
pub trait Observer: Named + serde::Serialize + serde::de::DeserializeOwned + 'static {
    /// The testcase finished execution, calculate any changes.
    #[inline]
    fn flush(&mut self) -> Result<(), AflError> {
        Ok(())
    }

    /// Resets the observer
    fn pre_exec(&mut self) -> Result<(), AflError>;

    /// This function is executed after each fuzz run
    #[inline]
    fn post_exec(&mut self) -> Result<(), AflError> {
        Ok(())
    }

    /// Serialize this observer's state only, to be restored later using deserialize_state
    /// As opposed to completely serializing the observer, this is only needed when the fuzzer is to be restarted
    /// If no state is needed to be kept, just return an empty vec.
    /// Example:
    /// >> The virgin_bits map in AFL needs to be in sync with the corpus
    #[inline]
    fn serialize_state(&mut self) -> Result<Vec<u8>, AflError> {
        Ok(vec![])
    }

    /// Restore the state from a given vec, priviously stored using `serialize_state`
    #[inline]
    fn deserialize_state(&mut self, serialized_state: &[u8]) -> Result<(), AflError> {
        let _ = serialized_state;
        Ok(())
    }
}

/// A hastkel-style tuple of observers
pub trait ObserversTuple:
    MatchNameAndType + MatchType + serde::Serialize + serde::de::DeserializeOwned
{
    /// Reset all executors in the tuple
    /// This is called right before the next execution.
    fn pre_exec_all(&mut self) -> Result<(), AflError>;
    /// Do whatever you need to do after a run.
    /// This is called right after the last execution
    fn post_exec_all(&mut self) -> Result<(), AflError>;
    //fn for_each(&self, f: fn(&dyn Observer));
    //fn for_each_mut(&mut self, f: fn(&mut dyn Observer));

    /// Serialize this tuple to a buf
    fn serialize(&self) -> Result<Vec<u8>, AflError> {
        Ok(postcard::to_allocvec(&self)?)
    }

    /// Deserilaize
    fn deserialize(&self, serialized: &[u8]) -> Result<Self, AflError> {
        Ok(postcard::from_bytes(serialized)?)
    }
}

impl ObserversTuple for () {
    fn pre_exec_all(&mut self) -> Result<(), AflError> {
        Ok(())
    }
    fn post_exec_all(&mut self) -> Result<(), AflError> {
        Ok(())
    }

    //fn for_each(&self, f: fn(&dyn Observer)) { }
    //fn for_each_mut(&mut self, f: fn(&mut dyn Observer)) { }
}

impl<Head, Tail> ObserversTuple for (Head, Tail)
where
    Head: Observer,
    Tail: ObserversTuple + TupleList,
{
    fn pre_exec_all(&mut self) -> Result<(), AflError> {
        self.0.pre_exec()?;
        self.1.pre_exec_all()
    }

    fn post_exec_all(&mut self) -> Result<(), AflError> {
        self.0.post_exec()?;
        self.1.post_exec_all()
    }

    /*fn for_each(&self, f: fn(&dyn Observer)) {
        f(&self.0);
        self.1.for_each(f)
    }

    fn for_each_mut(&mut self, f: fn(&mut dyn Observer)) {
        f(&mut self.0);
        self.1.for_each_mut(f)
    }*/
}

/// A simple observer, just overlooking the runtime of the target.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TimeObserver {
    name: String,
    start_time: Duration,
    last_runtime: Option<Duration>,
}

impl TimeObserver {
    /// Creates a new TimeObserver with the given name.
    pub fn new(name: &'static str) -> Self {
        Self {
            name: name.to_string(),
            start_time: Duration::from_secs(0),
            last_runtime: None,
        }
    }
}

impl Observer for TimeObserver {
    fn pre_exec(&mut self) -> Result<(), AflError> {
        self.last_runtime = None;
        self.start_time = current_time();
        Ok(())
    }

    fn post_exec(&mut self) -> Result<(), AflError> {
        self.last_runtime = Some(current_time() - self.start_time);
        Ok(())
    }
}

impl Named for TimeObserver {
    fn name(&self) -> &str {
        &self.name
    }
}

/// A MapObserver observes the static map, as oftentimes used for afl-like coverage information
pub trait MapObserver<T>: Observer
where
    T: Default + Copy,
{
    /// Get the map
    fn map(&self) -> &[T];

    /// Get the map (mutable)
    fn map_mut(&mut self) -> &mut [T];

    /// Get the number of usable entries in the map (all by default)
    fn usable_count(&self) -> usize {
        self.map().len()
    }

    /// Get the initial value for reset()
    fn initial(&self) -> T;

    /// Get the initial value for reset()
    fn initial_mut(&mut self) -> &mut T;

    /// Set the initial value for reset()
    fn set_initial(&mut self, initial: T);

    /// Reset the map
    #[inline]
    fn reset_map(&mut self) -> Result<(), AflError> {
        // Normal memset, see https://rust.godbolt.org/z/Trs5hv
        let initial = self.initial();
        let cnt = self.usable_count();
        for i in self.map_mut()[0..cnt].iter_mut() {
            *i = initial;
        }
        Ok(())
    }
}

/// The Map Observer retrieves the state of a map,
/// that will get updated by the target.
/// A well-known example is the AFL-Style coverage map.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
pub struct StdMapObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    map: ArrayMut<T>,
    initial: T,
    name: String,
}

impl<T> Observer for StdMapObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn pre_exec(&mut self) -> Result<(), AflError> {
        self.reset_map()
    }
}

impl<T> Named for StdMapObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<T> MapObserver<T> for StdMapObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn map(&self) -> &[T] {
        self.map.as_slice()
    }

    #[inline]
    fn map_mut(&mut self) -> &mut [T] {
        self.map.as_mut_slice()
    }

    #[inline]
    fn initial(&self) -> T {
        self.initial
    }

    #[inline]
    fn initial_mut(&mut self) -> &mut T {
        &mut self.initial
    }

    #[inline]
    fn set_initial(&mut self, initial: T) {
        self.initial = initial
    }
}

impl<T> StdMapObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new MapObserver
    pub fn new(name: &'static str, map: &'static mut [T]) -> Self {
        let initial = if map.len() > 0 { map[0] } else { T::default() };
        Self {
            map: ArrayMut::Cptr((map.as_mut_ptr(), map.len())),
            name: name.to_string(),
            initial,
        }
    }

    /// Creates a new MapObserver from a raw pointer
    pub fn new_from_ptr(name: &'static str, map_ptr: *mut T, len: usize) -> Self {
        unsafe {
            let initial = if len > 0 { *map_ptr } else { T::default() };
            StdMapObserver {
                map: ArrayMut::Cptr((map_ptr, len)),
                name: name.to_string(),
                initial,
            }
        }
    }
}

/// Overlooking a variable bitmap
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
pub struct VariableMapObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    map: ArrayMut<T>,
    size: Cptr<usize>,
    initial: T,
    name: String,
}

impl<T> Observer for VariableMapObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn pre_exec(&mut self) -> Result<(), AflError> {
        self.reset_map()
    }
}

impl<T> Named for VariableMapObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<T> MapObserver<T> for VariableMapObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn map(&self) -> &[T] {
        self.map.as_slice()
    }

    #[inline]
    fn map_mut(&mut self) -> &mut [T] {
        self.map.as_mut_slice()
    }

    #[inline]
    fn usable_count(&self) -> usize {
        *self.size.as_ref()
    }

    #[inline]
    fn initial(&self) -> T {
        self.initial
    }

    #[inline]
    fn initial_mut(&mut self) -> &mut T {
        &mut self.initial
    }

    #[inline]
    fn set_initial(&mut self, initial: T) {
        self.initial = initial
    }
}

impl<T> VariableMapObserver<T>
where
    T: Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new MapObserver
    pub fn new(name: &'static str, map: &'static mut [T], size: &usize) -> Self {
        let initial = if map.len() > 0 { map[0] } else { T::default() };
        Self {
            map: ArrayMut::Cptr((map.as_mut_ptr(), map.len())),
            size: Cptr::Cptr(size as *const _),
            name: name.into(),
            initial,
        }
    }

    /// Creates a new MapObserver from a raw pointer
    pub fn new_from_ptr(
        name: &'static str,
        map_ptr: *mut T,
        max_len: usize,
        size_ptr: *const usize,
    ) -> Self {
        unsafe {
            let initial = if max_len > 0 { *map_ptr } else { T::default() };
            VariableMapObserver {
                map: ArrayMut::Cptr((map_ptr, max_len)),
                size: Cptr::Cptr(size_ptr),
                name: name.into(),
                initial,
            }
        }
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {

    use crate::{
        observers::{StdMapObserver, TimeObserver},
        tuples::{tuple_list, tuple_list_type, Named},
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
