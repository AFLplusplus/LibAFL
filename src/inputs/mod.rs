pub mod bytes;

use std::fs::File;
use std::io::Read;
use std::io::Write;

use crate::Error;

pub trait Input {
    fn to_file(&self, path: &str) -> Result<(), Error> {
        let mut file = File::create(path)?;
        file.write_all(self.serialize()?)?;
        Ok(())
    }

    fn from_file(&mut self, path: &str) -> Result<(), Error> {
        let mut file = File::create(path)?;
        let mut buf = vec![];
        file.read_to_end(&mut buf)?;
        self.deserialize(&buf)?;
        Ok(())
    }

    fn serialize(&self) -> Result<&[u8], Error>;

    fn deserialize(&mut self, buf: &[u8]) -> Result<(), Error>;
}
