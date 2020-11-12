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

use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AflError {
    #[error("Error in Serialization: `{0}`")]
    Serialize(String),
    #[error("File IO failed")]
    File(#[from] io::Error),
    #[error("Optional value `{0}` was not set")]
    EmptyOptional(String),
    #[error("Key `{0}` not in Corpus")]
    KeyNotFound(String),
    #[error("No items in {0}")]
    Empty(String),
    #[error("All elements have been processed in {0} iterator")]
    IteratorEnd(String),
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    #[error("Unknown error: {0}")]
    Unknown(String),
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
