use crate::inputs::Input;
use crate::AflError;

use hashbrown::HashMap;
use std::path::PathBuf;

pub trait TestcaseMetadata {
    fn name(&self) -> &'static str;
}

/*
pub trait TestcaseTrait<I: Input> {
    /// Make sure to return a valid input instance loading it from disk if not in memory
    fn load_input(&mut self) -> Result<&I, AflError>;

    /// Get the input, if any
    fn input(&self) -> &Option<I>;

    /// Get the input, if any (mutable)
    fn input_mut(&mut self) -> &mut Option<I>;

    /// Get the filename, if any
    fn filename(&self) -> &Option<PathBuf>;

    /// Get the filename, if any (mutable)
    fn filename_mut(&mut self, filename: PathBuf) -> &mut &Option<PathBuf>;

    /// Get all the metadatas into an HashMap
    fn metadatas(&mut self) -> &mut HashMap<String, Box<dyn TestcaseMetadata>>;
}
*/

#[derive(Default)]
pub struct Testcase<I>
where
    I: Input,
{
    input: Option<I>, // TODO remove box
    filename: Option<PathBuf>,
    metadatas: HashMap<&'static str, Box<dyn TestcaseMetadata>>,
}

impl<I> Testcase<I>
where
    I: Input,
{
    /// Make sure to return a valid input instance loading it from disk if not in memory
    pub fn load_input(&mut self) -> Result<&I, AflError> {
        // TODO: Implement cache to disk
        match self.input.as_ref() {
            Some(i) => Ok(i),
            None => Err(AflError::NotImplemented("load_input".to_string())),
        }
    }

    /// Get the input, if any
    pub fn input(&self) -> &Option<I> {
        &self.input
    }
    /// Get the input, if any (mutable)
    pub fn input_mut(&mut self) -> &mut Option<I> {
        &mut self.input
    }
    /// Set the input
    pub fn set_input(&mut self, input: Option<I>) {
        self.input = input;
    }

    /// Get the filename, if any
    pub fn filename(&self) -> &Option<PathBuf> {
        &self.filename
    }
    /// Get the filename, if any (mutable)
    pub fn filename_mut(&mut self) -> &mut Option<PathBuf> {
        &mut self.filename
    }
    /// Set the filename
    pub fn set_filename(&mut self, filename: Option<PathBuf>) {
        self.filename = filename;
    }

    /// Get all the metadatas into an HashMap
    pub fn metadatas(&mut self) -> &mut HashMap<&'static str, Box<dyn TestcaseMetadata>> {
        &mut self.metadatas
    }

    /// Add a metadata
    pub fn add_metadata(&mut self, meta: Box<dyn TestcaseMetadata>) {
        self.metadatas.insert(meta.name(), meta);
    }

    /// Create a new DefaultTestcase instace given an input
    pub fn new(input: I) -> Self {
        Testcase {
            input: Some(input),
            filename: None,
            metadatas: HashMap::default(),
        }
    }

    /// Create a new DefaultTestcase instace given an input and a filename
    pub fn new_with_filename(input: I, filename: PathBuf) -> Self {
        Testcase {
            input: Some(input),
            filename: Some(filename),
            metadatas: HashMap::default(),
        }
    }
}
