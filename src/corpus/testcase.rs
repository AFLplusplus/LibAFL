use crate::inputs::Input;
use crate::AflError;

use hashbrown::HashMap;
use core::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

// TODO: Give example
/// Metadata for a testcase
pub trait TestcaseMetadata {
    /// The name of this metadata - used to find it in the list of avaliable metadatas
    fn name(&self) -> &'static str;
}

/// An entry in the Testcase Corpus
#[derive(Default)]
pub struct Testcase<I>
where
    I: Input,
{
    /// The input of this testcase
    input: Option<I>, // TODO remove box
    /// Filename, if this testcase is backed by a file in the filesystem
    filename: Option<PathBuf>,
    /// Map of metadatas associated with this testcase
    metadatas: HashMap<&'static str, Box<dyn TestcaseMetadata>>,
}

/// Impl of a testcase
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

    /// Create a new Testcase instace given an input
    pub fn new(input: I) -> Self {
        Testcase {
            input: Some(input),
            filename: None,
            metadatas: HashMap::default(),
        }
    }

    /// Create a new Testcase instace given an input and a filename
    pub fn with_filename(input: I, filename: PathBuf) -> Self {
        Testcase {
            input: Some(input),
            filename: Some(filename),
            metadatas: HashMap::default(),
        }
    }

    /// Create a new Testcase instace given an input behind a Rc RefCell
    pub fn new_rr(input: I) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self::new(input)))
    }

    /// Create a new Testcase instace given an input and a filename behind a Rc RefCell
    pub fn with_filename_rr(input: I, filename: PathBuf) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self::with_filename(input, filename)))
    }
}
