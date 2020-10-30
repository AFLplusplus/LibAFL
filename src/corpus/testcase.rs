use crate::inputs::Input;
use crate::AflError;

use hashbrown::HashMap;
use std::path::PathBuf;

pub trait TestcaseMetadata {}

pub trait Testcase {

    fn load_input(&mut self) -> Result<&Box<dyn Input>, AflError>;

    fn get_input(&self) -> Option<& Box<dyn Input>>;

    fn is_on_disk(&self) -> bool;

    fn get_filename(&self) -> Option<& PathBuf>;

    fn set_filename(&mut self, filename: PathBuf);

    fn get_metadatas(&mut self) -> &mut HashMap<String, Box<dyn TestcaseMetadata>>;

}

#[derive(Default)]
pub struct SimpleTestcase {
    input: Option<Box<dyn Input>>,
    // is_on_disk: bool, // not needed, look at the Option
    filename: Option<PathBuf>,
    metadatas: HashMap<String, Box<dyn TestcaseMetadata>>,
}

impl Testcase for SimpleTestcase {
    fn load_input(&mut self) -> Result<&Box<dyn Input>, AflError> {
        // TODO: Implement cache to disk
        self.input.as_ref().ok_or(AflError::NotImplemented("load_input".to_string()))
    }

    fn get_input(&self) -> Option<& Box<dyn Input>> {
        self.input.as_ref()
    }

    fn is_on_disk(&self) -> bool {
        !self.input.is_some() && self.filename.is_some()
    }

    fn get_filename(&self) -> Option<& PathBuf> {
        self.filename.as_ref()
    }

    fn set_filename(&mut self, filename: PathBuf) {
        self.filename = Some(filename)
    }

    fn get_metadatas(&mut self) -> &mut HashMap<String, Box<dyn TestcaseMetadata>> {
        &mut self.metadatas
    }
}

impl SimpleTestcase {
    pub fn new(input: Box<dyn Input>) -> Self {
        SimpleTestcase {
            input: Some(input),
            filename: None,
            metadatas: HashMap::default(),
        }
    }
}
