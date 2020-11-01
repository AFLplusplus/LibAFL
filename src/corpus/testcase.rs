use crate::inputs::Input;
use crate::AflError;

use hashbrown::HashMap;
use std::path::PathBuf;

pub trait TestcaseMetadata {}

/*
pub trait TestcaseTrait<InputT: Input> {
    /// Make sure to return a valid input instance loading it from disk if not in memory
    fn load_input(&mut self) -> Result<&Box<InputT>, AflError>;

    /// Get the input, if any
    fn input(&self) -> &Option<Box<InputT>>;

    /// Get the input, if any (mutable)
    fn input_mut(&mut self) -> &mut Option<Box<InputT>>;

    /// Get the filename, if any
    fn filename(&self) -> &Option<PathBuf>;

    /// Get the filename, if any (mutable)
    fn filename_mut(&mut self, filename: PathBuf) -> &mut &Option<PathBuf>;

    /// Get all the metadatas into an HashMap
    fn metadatas(&mut self) -> &mut HashMap<String, Box<dyn TestcaseMetadata>>;
}
*/

#[derive(Default)]
pub struct Testcase<InputT: Input> {
    input: Option<Box<InputT>>,
    filename: Option<PathBuf>,
    metadatas: HashMap<String, Box<dyn TestcaseMetadata>>,
}

impl<InputT: Input> Testcase<InputT> {
    /// Make sure to return a valid input instance loading it from disk if not in memory
    pub fn load_input(&mut self) -> Result<&Box<InputT>, AflError> {
        // TODO: Implement cache to disk
        self.input.as_ref().ok_or(AflError::NotImplemented("load_input".to_string()))
    }

    /// Get the input, if any
    pub fn input(&self) -> &Option<Box<InputT>> {
        &self.input
    }

    /// Get the input, if any (mutable)
    pub fn input_mut(&mut self) -> &mut Option<Box<InputT>> {
        &mut self.input
    }

    /// Get the filename, if any
    pub fn filename(&self) -> &Option<PathBuf> {
        &self.filename
    }

    /// Get the filename, if any (mutable)
    pub fn filename_mut(&mut self, filename: PathBuf) -> &mut Option<PathBuf> {
        &mut self.filename
    }

    /// Get all the metadatas into an HashMap
    pub fn metadatas(&mut self) -> &mut HashMap<String, Box<dyn TestcaseMetadata>> {
        &mut self.metadatas
    }

    /// Create a new DefaultTestcase instace given an input
    pub fn new(input: Box<InputT>) -> Self {
        Testcase {
            input: Some(input),
            filename: None,
            metadatas: HashMap::default(),
        }
    }

    /// Create a new DefaultTestcase instace given an input and a filename
    pub fn new_with_filename(input: Box<InputT>, filename: &PathBuf) -> Self {
        Testcase {
            input: Some(input),
            filename: filename,
            metadatas: HashMap::default(),
        }
    }
}
