extern crate alloc;

use crate::inputs::Input;
use crate::AflError;

use alloc::rc::Rc;
use core::cell::RefCell;
use core::convert::Into;
use hashbrown::HashMap;
#[cfg(feature = "std")]
use std::fs::File;
#[cfg(feature = "std")]
use std::io::Write;
#[cfg(feature = "std")]
use std::path::Path;

// TODO: Give example
/// Metadata for a testcase
pub trait TestcaseMetadata {
    /// The name of this metadata - used to find it in the list of avaliable metadatas
    fn name(&self) -> &'static str;
}

/*
pub trait Testcase<I, T>
where
    I: Input,
    T: TestcaseMetadata,
{

    fn input(&mut self) -> Option<I>

    input: Option<I>,
    /// Filename, if this testcase is backed by a file in the filesystem
    filename: Option<String>,
    /// Map of metadatas associated with this testcase
    metadatas: HashMap<&'static str, Box<dyn TestcaseMetadata>>,

}
*/

pub enum FileBackedTestcase<I, P> {
    /// A testcase on disk, not yet loaded
    Stored { filename: P },

    /// A testcase that has been loaded, and not yet dirtied.
    /// The input should be equal to the on-disk state.
    Loaded { input: I, filename: P },

    /// A testcase that has been mutated, but not yet written to disk
    Dirty { input: I, filename: P },
}

impl<I, P> FileBackedTestcase<I, P>
where
    I: Input,
    P: AsRef<Path>,
{
    /// Load a testcase from disk if it is not already loaded.
    ///
    /// # Errors
    /// Errors if the testcase is [Dirty](FileBackedTestcase::Dirty)
    pub fn load(self) -> Result<Self, AflError> {
        match self {
            Self::Stored { filename } => {
                let input = I::from_file(&filename)?;
                Ok(Self::Loaded { filename, input })
            }
            Self::Loaded {
                input: _,
                filename: _,
            } => Ok(self),
            _ => Err(AflError::IllegalState(
                "Attempted load on dirty testcase".into(),
            )),
        }
    }

    /// Make sure that the in-memory state is syncd to disk, and load it from disk if
    /// Nece
    pub fn refresh(self) -> Result<Self, AflError> {
        match self {
            Self::Dirty {
                input: _,
                filename: _,
            } => self.save(),
            other => other.load(),
        }
    }

    /// Writes changes to disk
    pub fn save(self) -> Result<Self, AflError> {
        match self {
            Self::Loaded {
                input: _,
                filename: _,
            } => Ok(self),
            Self::Dirty { input, filename } => {
                let mut file = File::create(&filename)?;
                file.write_all(input.serialize()?)?;

                Ok(Self::Loaded { input, filename })
            }
            Self::Stored { filename } => Err(AflError::IllegalState(format!(
                "Tried to store to {:?} without input (in stored state)",
                filename.as_ref()
            ))),
        }
    }

    // Removes contents of this testcase from memory
    pub fn unload(self) -> Result<Self, AflError> {
        match self {
            Self::Loaded { input: _, filename } => Ok(Self::Stored { filename }),
            Self::Stored { filename: _ } => Ok(self),
            Self::Dirty {
                filename: _,
                input: _,
            } => self.save(),
        }
    }
}

/// An entry in the Testcase Corpus
#[derive(Default)]
pub struct Testcase<I>
where
    I: Input,
{
    /// The input of this testcase
    input: Option<I>,
    /// Filename, if this testcase is backed by a file in the filesystem
    filename: Option<String>,
    /// Map of metadatas associated with this testcase
    metadatas: HashMap<&'static str, Box<dyn TestcaseMetadata>>,
}

impl<I> Into<Rc<RefCell<Self>>> for Testcase<I>
where
    I: Input,
{
    fn into(self) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(self))
    }
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
            None => Err(AflError::NotImplemented("load_input".into())),
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
    pub fn filename(&self) -> &Option<String> {
        &self.filename
    }
    /// Get the filename, if any (mutable)
    pub fn filename_mut(&mut self) -> &mut Option<String> {
        &mut self.filename
    }
    /// Set the filename
    pub fn set_filename(&mut self, filename: Option<String>) {
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
    pub fn new<T>(input: T) -> Self 
    where T: Into<I>{
        Testcase {
            input: Some(input.into()),
            filename: None,
            metadatas: HashMap::default(),
        }
    }

    /// Create a new Testcase instace given an input and a filename
    pub fn with_filename(input: I, filename: String) -> Self {
        Testcase {
            input: Some(input),
            filename: Some(filename),
            metadatas: HashMap::default(),
        }
    }
}
