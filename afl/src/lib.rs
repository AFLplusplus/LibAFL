/*!
Welcome to libAFL
*/

#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;
#[macro_use]
extern crate static_assertions;

pub mod corpus;
pub mod events;
pub mod executors;
pub mod feedbacks;
pub mod generators;
pub mod inputs;
pub mod llmp;
pub mod metamap;
pub mod mutators;
pub mod observers;
pub mod serde_anymap;
pub mod shmem;
pub mod stages;
pub mod state;
pub mod tuples;
pub mod utils;

use alloc::string::String;
use core::fmt;
#[cfg(feature = "std")]
use std::{env::VarError, io, num::ParseIntError, string::FromUtf8Error};

/// Main error struct for AFL
#[derive(Debug)]
pub enum AflError {
    /// Serialization error
    Serialize(String),
    /// File related error
    #[cfg(feature = "std")]
    File(io::Error),
    /// Optional val was supposed to be set, but isn't.
    EmptyOptional(String),
    /// Key not in Map
    KeyNotFound(String),
    /// No elements in the current item
    Empty(String),
    /// End of iteration
    IteratorEnd(String),
    /// This is not supported (yet)
    NotImplemented(String),
    /// You're holding it wrong
    IllegalState(String),
    /// The argument passed to this method or function is not valid
    IllegalArgument(String),
    /// Something else happened
    Unknown(String),
}

impl fmt::Display for AflError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Serialize(s) => write!(f, "Error in Serialization: `{0}`", &s),
            #[cfg(feature = "std")]
            Self::File(err) => write!(f, "File IO failed: {:?}", &err),
            Self::EmptyOptional(s) => write!(f, "Optional value `{0}` was not set", &s),
            Self::KeyNotFound(s) => write!(f, "Key `{0}` not in Corpus", &s),
            Self::Empty(s) => write!(f, "No items in {0}", &s),
            Self::IteratorEnd(s) => {
                write!(f, "All elements have been processed in {0} iterator", &s)
            }
            Self::NotImplemented(s) => write!(f, "Not implemented: {0}", &s),
            Self::IllegalState(s) => write!(f, "Illegal state: {0}", &s),
            Self::IllegalArgument(s) => write!(f, "Illegal argument: {0}", &s),
            Self::Unknown(s) => write!(f, "Unknown error: {0}", &s),
        }
    }
}

/// Stringify the postcard serializer error
impl From<postcard::Error> for AflError {
    fn from(err: postcard::Error) -> Self {
        Self::Serialize(format!("{:?}", err))
    }
}

/// Create an AFL Error from io Error
#[cfg(feature = "std")]
impl From<io::Error> for AflError {
    fn from(err: io::Error) -> Self {
        Self::File(err)
    }
}

#[cfg(feature = "std")]
impl From<FromUtf8Error> for AflError {
    fn from(err: FromUtf8Error) -> Self {
        Self::Unknown(format!("Could not convert byte to utf-8: {:?}", err))
    }
}

#[cfg(feature = "std")]
impl From<VarError> for AflError {
    fn from(err: VarError) -> Self {
        Self::Empty(format!("Could not get env var: {:?}", err))
    }
}

#[cfg(feature = "std")]
impl From<ParseIntError> for AflError {
    fn from(err: ParseIntError) -> Self {
        Self::Unknown(format!("Failed to parse Int: {:?}", err))
    }
}
