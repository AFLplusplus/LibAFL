//! This module will log every function that an execution has executed
//! In addition it will lookup from a database to profile what features are there in the executed path

use alloc::{borrow::Cow, vec::Vec};
use core::fmt::Debug;
use std::path::Path;

use libafl_bolts::{ownedref::OwnedMutPtr, Error, Named};
use serde::{Deserialize, Serialize};

use crate::{inputs::UsesInput, observers::Observer};

/// A simple observer with a list of things.
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned + serde::Serialize")]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct ProfilerObserver<T> {
    name: Cow<'static, str>,
    /// The list
    list: OwnedMutPtr<Vec<T>>,
    // to do add map
}

impl<T> ProfilerObserver<T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`ProfilerObserver`] with the given name.
    ///
    /// # Safety
    /// Will dereference the list.
    /// The list may not move in memory.
    #[must_use]
    pub fn new<P>(name: &'static str, list: OwnedMutPtr<Vec<T>>, _json_path: P) -> Self
    where
        P: AsRef<Path>,
    {
        // todo; load json stuff
        Self {
            name: Cow::from(name),
            list,
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

    // todo add the map getter/seter
}

impl<S, T> Observer<S> for ProfilerObserver<T>
where
    S: UsesInput,
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.list.as_mut().clear();
        Ok(())
    }
}

impl<T> Named for ProfilerObserver<T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}
