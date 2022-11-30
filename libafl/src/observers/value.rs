//! A simple observer with a single value.

use alloc::string::{String, ToString};
use core::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::{bolts::tuples::Named, inputs::UsesInput, Error};

use super::Observer;

/// A simple observer with a single value.
///
/// The intent is that the value is something with interior mutability (e.g., a
/// `RefCell`), which the target could write to even though this observer owns
/// it.
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
pub struct ValueObserver<T>
where
    T: Debug + Serialize,
{
    /// The name of this observer.
    name: String,
    /// The value.
    pub value: T,
}

impl<T> ValueObserver<T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`ValueObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str, value: T) -> Self {
        Self {
            name: name.to_string(),
            value,
        }
    }

    /// Get a reference to the underlying value.
    #[must_use]
    pub fn get_ref(&self) -> &T {
        &self.value
    }

    /// Get a mutable reference to the underlying value.
    #[must_use]
    pub fn get_ref_mut(&mut self) -> &mut T {
        &mut self.value
    }

    /// Replace the value, return the old one.
    pub fn replace(&mut self, new_value: T) -> T {
        core::mem::replace(&mut self.value, new_value)
    }

    /// Replace the value with a default, return the old one.
    pub fn take(&mut self) -> T
    where
        T: core::default::Default,
    {
        self.replace(<T as Default>::default())
    }
}

/// Resets the value to its default before each execution.
impl<'a, S, T> Observer<S> for ValueObserver<T>
where
    S: UsesInput,
    T: Debug + Default + Serialize + serde::de::DeserializeOwned,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.value = <T as Default>::default();
        Ok(())
    }
}

impl<'a, T> Named for ValueObserver<T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    fn name(&self) -> &str {
        &self.name
    }
}
