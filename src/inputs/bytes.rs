use crate::inputs::Input;
use crate::AflError;

#[derive(Clone, Debug, Default)]
pub struct BytesInput {
    bytes: Vec<u8>,
}

impl Input for BytesInput {
    fn serialize(&self) -> Result<&[u8], AflError> {
        Ok(&self.bytes)
    }
    fn deserialize(&mut self, buf: &[u8]) -> Result<(), AflError> {
        self.bytes.truncate(0);
        self.bytes.extend_from_slice(buf);
        Ok(())
    }
}
