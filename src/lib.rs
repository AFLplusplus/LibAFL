#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

pub mod corpus;
pub mod engines;
pub mod executors;
pub mod feedbacks;
pub mod inputs;
pub mod monitors;
pub mod mutators;
pub mod observers;
pub mod stages;
pub mod utils;

use alloc::string::String;
use core::fmt;
#[cfg(feature = "std")]
use std::io;

/// Main error struct for AFL
#[derive(Debug)]
pub enum AflError {
    Serialize(String),
    #[cfg(feature = "std")]
    File(io::Error),
    EmptyOptional(String),
    KeyNotFound(String),
    Empty(String),
    IteratorEnd(String),
    NotImplemented(String),
    IllegalState(String),
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
            Self::Unknown(s) => write!(f, "Unknown error: {0}", &s),
        }
    }
}

#[cfg(feature = "std")]
impl From<io::Error> for AflError {
    fn from(err: io::Error) -> Self {
        Self::File(err)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
