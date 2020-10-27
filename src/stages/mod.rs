use crate::corpus::Testcase;
use crate::inputs::Input;
use crate::AflError;
/// Stages
pub trait Stage {
    fn perform(&mut self, input: &dyn Input, entry: &mut dyn Testcase) -> Result<(), AflError>;
}
