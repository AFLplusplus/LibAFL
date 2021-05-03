//! Compression of events passed between a broker and clients.
//! Currently we use the gzip compression algorithm for its fast decompression performance.

#[cfg(feature = "llmp_compression")]
use crate::Error;
use alloc::vec::Vec;
use compression::prelude::*;
use core::fmt::Debug;

/// Compression for your stream compression needs.
#[derive(Debug)]
pub struct GzipCompressor {
    /// If less bytes than threshold are being passed to `compress`, the payload is not getting compressed.
    threshold: usize,
}

impl GzipCompressor {
    /// If the buffer is at lest larger as large as the `threshold` value, we compress the buffer.
    /// When given a `threshold` of `0`, the `GzipCompressor` will always compress.
    pub fn new(threshold: usize) -> Self {
        Self { threshold }
    }
}

impl GzipCompressor {
    /// Compression.
    /// If the buffer is smaller than the threshold of this compressor, `None` will be returned.
    /// Else, the buffer is compressed.
    pub fn compress(&self, buf: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if buf.len() >= self.threshold {
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
    #[allow(clippy::unused_self)]
    pub fn decompress(&self, buf: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(buf
            .iter()
            .cloned()
            .decode(&mut GZipDecoder::new())
            .collect::<Result<Vec<_>, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use crate::bolts::compress::GzipCompressor;

    #[test]
    fn test_compression() {
        let compressor = GzipCompressor::new(1);
        assert!(
            compressor
                .decompress(&compressor.compress(&[1u8; 1024]).unwrap().unwrap())
                .unwrap()
                == vec![1u8; 1024]
        );
    }

    #[test]
    fn test_threshold() {
        let compressor = GzipCompressor::new(1024);
        assert!(compressor.compress(&[1u8; 1023]).unwrap().is_none());
        assert!(compressor.compress(&[1u8; 1024]).unwrap().is_some());
    }
}
