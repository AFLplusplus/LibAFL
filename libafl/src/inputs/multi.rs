//! Definitions for inputs which have multiple distinct subcomponents.
//!
//! Unfortunately, since both [`serde::de::Deserialize`] and [`Clone`] require [`Sized`], it is not
//! possible to dynamically define a single input with dynamic typing. As such, [`MultipartInput`]
//! requires that each subcomponent be the same subtype.

use alloc::{string::String, vec::Vec};

use libafl_bolts::Error;
use serde::{Deserialize, Serialize};

use crate::inputs::Input;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultipartInput<I> {
    parts: Vec<I>,
    names: Vec<String>,
}

impl<I> MultipartInput<I> {
    pub fn new() -> Self {
        Self {
            parts: Vec::new(),
            names: Vec::new(),
        }
    }

    pub fn parts(&self) -> &Vec<I> {
        &self.parts
    }

    pub fn part_mut(&mut self, idx: usize) -> Option<&mut I> {
        self.parts.get_mut(idx)
    }

    pub fn names(&self) -> &Vec<String> {
        &self.names
    }

    pub fn part_by_name(&self, name: &str) -> Option<&I> {
        self.names()
            .iter()
            .position(|s| s == name)
            .map(|idx| &self.parts()[idx])
    }

    pub fn part_by_name_mut(&mut self, name: &str) -> Option<&mut I> {
        self.names()
            .iter()
            .position(|s| s == name)
            .map(|idx| &mut self.parts[idx])
    }

    pub fn add_part(&mut self, name: String, part: I) -> Result<(), Error> {
        if self.names.contains(&name) {
            return Err(Error::illegal_argument(format!(
                "{} was already inserted into this multipart input!",
                name
            )));
        }
        self.parts.push(part);
        self.names.push(name);
        Ok(())
    }
}

impl<I> Input for MultipartInput<I>
where
    I: Input,
{
    fn generate_name(&self, idx: usize) -> String {
        self.names
            .iter()
            .cloned()
            .zip(self.parts.iter().map(|i| i.generate_name(idx)))
            .map(|(name, generated)| format!("{name}-{generated}"))
            .collect::<Vec<_>>()
            .join(",")
    }
}
