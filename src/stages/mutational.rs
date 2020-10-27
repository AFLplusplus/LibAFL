use std::Vec;
use crate::mutators::Mutator;
use crate::inputs::Input;

pub struct MutationalStage {
    mutators: Vec<Box<dyn Mutator>>;
}

impl Stage for MutationalStage {

    fn Perform(&mut self, input: &Input, entry: &mut Entry) -> Result<(), AflError> {
        // TODO: Implement me
        Err(AflError::Unknown);
    }

}