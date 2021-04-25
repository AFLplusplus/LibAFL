use compression::prelude::*;
use alloc::vec::Vec;

pub trait Compressor
{
    fn pre_exec(&mut self) -> Result<(), Error>

    fn compress(&mut self, buf : &[u8]) -> Vec<u8>

    fn decompress(&mut self, buf : &[u8]) -> Vec<u8>

    fn post_exec(&mut self) -> Result<(), Error>
}

pub struct GzipCompressor{
    threshold : usize,
}

impl GzipCompressor{
    pub fn new(threshold : usize) -> Self{
        Self{
            threshold : threshold,
        }
    }
}


impl GzipCompressor for Compressor
{
    fn pre_exec(&mut self) -> Result<(), Error>{
        Ok(())
    }

    fn compress(&mut self, buf : &[u8]) -> Vec<u8>{
        if buf.len() > threshold{
            //compress if the buffer is large enough
            let compressed = buf
            .into_iter()
            .cloned()
            .encode(&mut GZipEncoder::new(), Action::Finish)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
            compressed
        }
        else{
            buf
        }
    }

    fn decompress(&mut self, buf : &[u8]) -> Vec<u8>{
        let decompressed: Vec<u8> = buf.into_iter().cloned()
            .decode(&mut GZipDecoder::new())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        decompressed
    }

    fn post_exec(&mut self) -> Result<(), Error>{
        Ok(())
    }
}