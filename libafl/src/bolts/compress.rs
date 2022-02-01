//! Compression of events passed between a broker and clients.
//! Currently we use the gzip compression algorithm for its fast decompression performance.

use crate::Error;
use alloc::vec::Vec;
use core::fmt::Debug;
use miniz_oxide::{
    deflate::compress_to_vec, deflate::CompressionLevel, inflate::decompress_to_vec,
};

/// Compression for your stream compression needs.
#[derive(Debug)]
pub struct GzipCompressor {
    /// If less bytes than threshold are being passed to `compress`, the payload is not getting compressed.
    threshold: usize,
}

impl GzipCompressor {
    /// If the buffer is at least larger as large as the `threshold` value, we compress the buffer.
    /// When given a `threshold` of `0`, the `GzipCompressor` will always compress.
    #[must_use]
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
            let compressed = compress_to_vec(buf, CompressionLevel::BestSpeed as u8);
            Ok(Some(compressed))
        } else {
            Ok(None)
        }
    }

    /// Decompression.
    /// Flag is used to indicate if it's compressed or not
    #[allow(clippy::unused_self)]
    pub fn decompress(&self, buf: &[u8]) -> Result<Vec<u8>, Error> {
        let decompressed = decompress_to_vec(buf);

        match decompressed {
            Ok(buf) => Ok(buf),
            Err(_) => Err(Error::Compression),
        }
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
