//! Compression of events passed between a broker and clients.
//! Currently we use the gzip compression algorithm for its fast decompression performance.

#[cfg(feature = "llmp_compress")]
use crate::{
    bolts::llmp::{Flag, LLMP_FLAG_COMPRESSED},
    Error,
};
use alloc::vec::Vec;
use compression::prelude::*;
use core::fmt::Debug;

#[derive(Debug)]
pub struct GzipCompressor {
    threshold: usize,
}

impl GzipCompressor {
    /// If the buffer is larger than the threshold value, we compress the buffer.
    pub fn new(threshold: usize) -> Self {
        GzipCompressor { threshold }
    }
}

impl GzipCompressor {
    /// Compression.
    /// The buffer is compressed with the gzip algo
    pub fn compress(&self, buf: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if buf.len() > self.threshold {
            //compress if the buffer is large enough
            let compressed = buf
                .iter()
                .cloned()
                .encode(&mut GZipEncoder::new(), Action::Finish)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Some(compressed))
        } else {
            Ok(None)
        }
    }

    /// Decompression.
    /// Flag is used to indicate if it's compressed or not
    pub fn decompress(&self, flags: Flag, buf: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if flags & LLMP_FLAG_COMPRESSED == LLMP_FLAG_COMPRESSED {
            let decompressed: Vec<u8> = buf
                .iter()
                .cloned()
                .decode(&mut GZipDecoder::new())
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Some(decompressed))
        } else {
            Ok(None)
        }
    }
}
