use crate::bolts::llmp::{Flag, Tag, LLMP_FLAG_COMPRESSED};
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

impl GzipCompressor {
    pub fn compress(&self, buf: &[u8]) -> Option<Vec<u8>> {
        if buf.len() > self.threshold {
            let t1 = crate::utils::current_time();
            //compress if the buffer is large enough
            let compressed = buf
                .into_iter()
                .cloned()
                .encode(&mut GZipEncoder::new(), Action::Finish)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let t2 = crate::utils::current_time();
            println!(
                "fn compress with compression {} nano sec",
                (t2 - t1).as_nanos()
            );
            println!("memory saved {} bytes", buf.len() - compressed.len());
            Some(compressed)
        } else {
            let t1 = crate::utils::current_time();
            let t2 = crate::utils::current_time();
            println!(
                "fn compress without compression {} nano sec",
                (t2 - t1).as_nanos()
            );
            None
        }
    }

    pub fn decompress(&self, _tag: Tag, flag: Flag, buf: &[u8]) -> Option<Vec<u8>> {
        if flag & LLMP_FLAG_COMPRESSED == LLMP_FLAG_COMPRESSED {
            let t1 = crate::utils::current_time();
            let decompressed: Vec<u8> = buf
                .into_iter()
                .cloned()
                .decode(&mut GZipDecoder::new())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let t2 = crate::utils::current_time();
            println!(
                "fn decompress with decompression {} nano sec",
                (t2 - t1).as_nanos()
            );
            Some(decompressed)
        } else {
            let t1 = crate::utils::current_time();
            let t2 = crate::utils::current_time();
            println!(
                "fn decompress without decompression {} nano sec",
                (t2 - t1).as_nanos()
            );
            None
        }
    }
}
