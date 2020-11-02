use crate::corpus::Testcase;
use crate::inputs::Input;
use crate::AflError;
/// Stages
pub trait Stage<InputT: Input> {
    fn perform(&mut self, input: &dyn Input, entry: &mut Testcase<InputT>) -> Result<(), AflError>;
}
