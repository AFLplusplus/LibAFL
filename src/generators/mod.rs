use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::cmp::min;

use crate::inputs::bytes::BytesInput;
use crate::inputs::Input;
use crate::utils::{HasRand, Rand};
use crate::AflError;

pub trait Generator<I>: HasRand
where
    I: Input,
{
    /// Generate a new input
    fn generate(&mut self) -> Result<I, AflError>;

    /// Generate a new dummy input
    fn generate_dummy(&self) -> I;
}

const DUMMY_BYTES_SIZE: usize = 64;

pub struct RandBytesGenerator<R> {
    rand: Rc<RefCell<R>>,
    max_size: usize,
}

impl<R> HasRand for RandBytesGenerator<R>
where
    R: Rand,
{
    type R = R;

    fn rand(&self) -> &Rc<RefCell<Self::R>> {
        &self.rand
    }
}

impl<R> Generator<BytesInput> for RandBytesGenerator<R>
where
    R: Rand,
{
    fn generate(&mut self) -> Result<BytesInput, AflError> {
        let size = self.rand_below(self.max_size as u64);
        let random_bytes: Vec<u8> = (0..size).map(|_| self.rand_below(256) as u8).collect();
        Ok(BytesInput::new(random_bytes))
    }

    fn generate_dummy(&self) -> BytesInput {
        let size = min(self.max_size, DUMMY_BYTES_SIZE);
        BytesInput::new(vec![0; size])
    }
}

pub struct RandPrintablesGenerator<R> {
    rand: Rc<RefCell<R>>,
    max_size: usize,
}

impl<R> HasRand for RandPrintablesGenerator<R>
where
    R: Rand,
{
    type R = R;

    fn rand(&self) -> &Rc<RefCell<Self::R>> {
        &self.rand
    }
}

impl<R> Generator<BytesInput> for RandPrintablesGenerator<R>
where
    R: Rand,
{
    fn generate(&mut self) -> Result<BytesInput, AflError> {
        let size = self.rand_below(self.max_size as u64);
        let printables = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz \t\n!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".as_bytes();
        let random_bytes: Vec<u8> = (0..size)
            .map(|_| printables[self.rand_below(printables.len() as u64) as usize])
            .collect();
        Ok(BytesInput::new(random_bytes))
    }

    fn generate_dummy(&self) -> BytesInput {
        let size = min(self.max_size, DUMMY_BYTES_SIZE);
        BytesInput::new(vec!['0' as u8; size])
    }
}
