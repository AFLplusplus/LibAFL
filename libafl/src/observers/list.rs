use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::Debug;

use libafl_bolts::{ownedref::OwnedMutPtr, Error, Named};
use serde::{Deserialize, Serialize};

use crate::{inputs::UsesInput, observers::Observer};

/// A simple observer with a list of things.
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct ListObserver<T>
where
    T: Debug + Serialize,
{
    name: String,
    /// The list
    list: OwnedMutPtr<Vec<T>>,
}

impl<T> ListObserver<T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`ListObserver`] with the given name.
    ///
    /// # Safety
    /// Will dereference the list.
    /// The list may not move in memory.
    #[must_use]
    pub unsafe fn new(name: &'static str, list: *mut Vec<T>) -> Self {
        Self {
            name: name.to_string(),
            list: OwnedMutPtr::Ptr(list),
        }
    }

    /// Get a list ref
    #[must_use]
    pub fn list(&self) -> &Vec<T> {
        self.list.as_ref()
    }

    /// Get a list mut
    #[must_use]
    pub fn list_mut(&mut self) -> &mut Vec<T> {
        self.list.as_mut()
    }
}

impl<S, T> Observer<S> for ListObserver<T>
where
    S: UsesInput,
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.list.as_mut().clear();
        Ok(())
    }
}

impl<T> Named for ListObserver<T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    fn name(&self) -> &str {
        &self.name
    }
}
