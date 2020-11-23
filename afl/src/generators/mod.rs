use alloc::vec::Vec;
use core::cmp::min;
use core::marker::PhantomData;

use crate::inputs::bytes::BytesInput;
use crate::inputs::Input;
use crate::utils::Rand;
use crate::AflError;

pub trait Generator<I, R>
where
    I: Input,
    R: Rand,
{
    /// Generate a new input
    fn generate(&mut self, rand: &mut R) -> Result<I, AflError>;

    /// Generate a new dummy input
    fn generate_dummy(&self) -> I;
}

const DUMMY_BYTES_SIZE: usize = 64;

pub struct RandBytesGenerator<R>
where
    R: Rand,
{
    max_size: usize,
    phantom: PhantomData<R>,
}

impl<R> Generator<BytesInput, R> for RandBytesGenerator<R>
where
    R: Rand,
{
    fn generate(&mut self, rand: &mut R) -> Result<BytesInput, AflError> {
        let mut size = rand.below(self.max_size as u64);
        if size == 0 {
            size = 1;
        }
        let random_bytes: Vec<u8> = (0..size).map(|_| rand.below(256) as u8).collect();
        Ok(BytesInput::new(random_bytes))
    }

    fn generate_dummy(&self) -> BytesInput {
        let size = min(self.max_size, DUMMY_BYTES_SIZE);
        BytesInput::new(vec![0; size])
    }
}

impl<R> RandBytesGenerator<R>
where
    R: Rand,
{
    pub fn new(max_size: usize) -> Self {
        RandBytesGenerator {
            max_size: max_size,
            phantom: PhantomData,
        }
    }
}

pub struct RandPrintablesGenerator<R> {
    max_size: usize,
    phantom: PhantomData<R>,
}

impl<R> Generator<BytesInput, R> for RandPrintablesGenerator<R>
where
    R: Rand,
{
    fn generate(&mut self, rand: &mut R) -> Result<BytesInput, AflError> {
        let mut size = rand.below(self.max_size as u64);
        if size == 0 {
            size = 1;
        }
        let printables = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz \t\n!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".as_bytes();
        let random_bytes: Vec<u8> = (0..size)
            .map(|_| printables[rand.below(printables.len() as u64) as usize])
            .collect();
        Ok(BytesInput::new(random_bytes))
    }

    fn generate_dummy(&self) -> BytesInput {
        let size = min(self.max_size, DUMMY_BYTES_SIZE);
        BytesInput::new(vec!['0' as u8; size])
    }
}

impl<R> RandPrintablesGenerator<R>
where
    R: Rand,
{
    pub fn new(max_size: usize) -> Self {
        RandPrintablesGenerator {
            max_size: max_size,
            phantom: PhantomData,
        }
    }
}
