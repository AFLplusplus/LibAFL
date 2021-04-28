//! Compression of events passed between a broker and clients
//! Currently we use the gzip compression algorithm for its fast decompression performance.

#[cfg(feature = "llmp_compress")]
use crate::{bolts::llmp::{Flag, LLMP_FLAG_COMPRESSED}, Error};
use alloc::vec::Vec;
use compression::prelude::*;
use core::fmt::Debug;

#[derive(Debug)]
pub struct GzipCompressor {
    threshold: usize,
}

impl GzipCompressor {
    pub fn new(threshold: usize) -> Self {
        GzipCompressor {
            threshold: threshold,
        }
    }
}



/// Compression
/// The buffer is compressed with gzip algo
impl GzipCompressor {
    pub fn compress(&self, buf: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if buf.len() > self.threshold {
            //let t1 = crate::utils::current_time();
            //compress if the buffer is large enough
            let compressed = buf
                .into_iter()
                .cloned()
                .encode(&mut GZipEncoder::new(), Action::Finish)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Some(compressed))
        } else {
            /*
            let t1 = crate::utils::current_time();
            let t2 = crate::utils::current_time();
            println!(
                "fn compress without compression {} nano sec",
                (t2 - t1).as_nanos()
            );
            */
            Ok(None)
        }
    }

    /// Decompression
    /// The buffer is decompressed, flag is used to indicate if it's compressed or not
    pub fn decompress(&self, flag: Flag, buf: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if flag & LLMP_FLAG_COMPRESSED == LLMP_FLAG_COMPRESSED {
            //let t1 = crate::utils::current_time();
            let decompressed: Vec<u8> = buf
                .into_iter()
                .cloned()
                .decode(&mut GZipDecoder::new())
                .collect::<Result<Vec<_>, _>>()?;
            //let t2 = crate::utils::current_time();
            /*
            println!(
                "fn decompress with decompression {} nano sec",
                (t2 - t1).as_nanos()
            );
            */
            Ok(Some(decompressed))
        } else {
            /*
            let t1 = crate::utils::current_time();
            let t2 = crate::utils::current_time();
            println!(
                "fn decompress without decompression {} nano sec",
                (t2 - t1).as_nanos()
            );
            */
            Ok(None)
        }
    }
}
