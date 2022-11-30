//! A simple observer with a single value.

use alloc::string::{String, ToString};
use core::cell::RefCell;
use core::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::{bolts::tuples::Named, inputs::UsesInput, Error};

use super::Observer;

/// A simple observer with a single value in a [`RefCell`].
///
/// The intent is that the target gets an immutable reference to the value, and
/// uses the interior mutability of the [`RefCell`] to write something to it.
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
pub struct ValueObserver<T>
where
    T: Debug + Serialize,
{
    name: String,
    /// The value.
    ///
    /// Wrapped in a [`RefCell`] so that the target/executor can mutate it, but
    /// we can still view it through this observer.
    pub value: RefCell<T>,
}

impl<T> ValueObserver<T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`ValueObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str, value: RefCell<T>) -> Self {
        Self {
            name: name.to_string(),
            value,
        }
    }
}

impl<'a, S, T> Observer<S> for ValueObserver<T>
where
    S: UsesInput,
    T: Debug + Default + Serialize + serde::de::DeserializeOwned,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.value.take();
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
