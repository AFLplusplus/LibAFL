//! A simple observer with a single value.

use alloc::{
    boxed::Box,
    string::{String, ToString},
};
use core::fmt::Debug;

use serde::{Deserialize, Serialize};

use super::Observer;
use crate::{
    bolts::{ownedref::OwnedRef, tuples::Named},
    inputs::UsesInput,
    Error,
};

/// A simple observer with a single value.
///
/// The intent is that the value is something with interior mutability (e.g., a
/// `RefCell`), which the target could write to even though this observer has a
/// reference to it.
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
pub struct ValueObserver<'a, T>
where
    T: Debug + Serialize,
{
    /// The name of this observer.
    name: String,
    /// The value.
    pub value: OwnedRef<'a, T>,
}

impl<'a, T> ValueObserver<'a, T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`ValueObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str, value: &'a T) -> Self {
        Self {
            name: name.to_string(),
            value: OwnedRef::Ref(value),
        }
    }

    /// Get a reference to the underlying value.
    ///
    /// ```
    /// # use libafl::observers::value::ValueObserver;
    /// let mut obs = ValueObserver::new("example", &2);
    /// assert_eq!(&2, obs.get_ref());
    /// ```
    #[must_use]
    pub fn get_ref(&self) -> &T {
        self.value.as_ref()
    }

    /// Set the value.
    ///
    /// ```
    /// # use libafl::observers::value::ValueObserver;
    /// let mut obs = ValueObserver::new("example", &2);
    /// obs.set(3);
    /// assert_eq!(3, obs.take());
    /// ```
    pub fn set(&mut self, new_value: T) {
        self.value = OwnedRef::Owned(Box::new(new_value));
    }

    /// Clone or move the current value out of this object.
    ///
    /// ```
    /// # use libafl::observers::value::ValueObserver;
    /// let mut obs = ValueObserver::new("example", &2);
    /// assert_eq!(2, obs.take());
    /// ```
    #[must_use]
    pub fn take(self) -> T
    where
        T: Clone,
    {
        match self.value {
            OwnedRef::Ref(r) => r.clone(),
            OwnedRef::Owned(v) => *v,
        }
    }
}

/// This *does not* reset the value inside the observer.
impl<'a, S, T> Observer<S> for ValueObserver<'a, T>
where
    S: UsesInput,
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        Ok(())
    }
}

impl<'a, T> Named for ValueObserver<'a, T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    fn name(&self) -> &str {
        &self.name
    }
}
