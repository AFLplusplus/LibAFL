use compression::prelude::*;
use alloc::vec::Vec;
use crate::Error;
use crate::bolts::llmp::Tag;
use core::fmt::Debug;

const LLMP_TAG_COMPRESS : Tag = 0x636f6d70;
#[derive(Debug)]
pub struct GzipCompressor{
    threshold : usize,
}

impl GzipCompressor{
    pub fn new(threshold : usize) -> Self{
        GzipCompressor {
            threshold : threshold,
        }
    }
}


impl GzipCompressor
{
    fn pre_exec(&self) -> Result<(), Error>{
        Ok(())
    }

    pub fn compress(&self, buf : &[u8]) -> Option<Vec<u8>>{
        if buf.len() > self.threshold {
            //compress if the buffer is large enough
            let compressed = buf
            .into_iter()
            .cloned()
            .encode(&mut GZipEncoder::new(), Action::Finish)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
            Some(compressed)
        }
        else{
            None
        }
    }

    pub fn decompress(&self, tag : Tag, buf : &[u8]) -> Option<Vec<u8>> {
        if tag == LLMP_TAG_COMPRESS{
                let decompressed: Vec<u8> = buf.into_iter().cloned()
                .decode(&mut GZipDecoder::new())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            Some(decompressed)
        }
        else{
            None
        }

    }

    fn post_exec(&self) -> Result<(), Error>{
        Ok(())
    }
}