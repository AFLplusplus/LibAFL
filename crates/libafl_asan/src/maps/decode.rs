use core::fmt::Debug;

use thiserror::Error;

pub trait MapDecode<T> {
    fn from_hex(c: u8) -> Result<T, MapDecodeError>;
    fn from_dec(c: u8) -> Result<T, MapDecodeError>;
}

impl<T: From<u8>> MapDecode<T> for T {
    fn from_hex(c: u8) -> Result<T, MapDecodeError> {
        let c = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'a' + 10,
            _ => Err(MapDecodeError::InvalidCharacter(c))?,
        };
        Ok(c.into())
    }

    fn from_dec(c: u8) -> Result<T, MapDecodeError> {
        let c = match c {
            b'0'..=b'9' => c - b'0',
            _ => Err(MapDecodeError::InvalidCharacter(c))?,
        };
        Ok(c.into())
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum MapDecodeError {
    #[error("Failed to convert: {0}")]
    InvalidCharacter(u8),
}
