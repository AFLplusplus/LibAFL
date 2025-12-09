use std::{cell::OnceCell, cmp::min, ptr, slice::from_raw_parts};

use libafl::inputs::HasTargetBytes;

use crate::{EmulatorDriverError, InputSetter, Qemu, emu::systemmode::SystemInputLocation};

#[derive(Clone, Debug)]
pub struct StdNyxInputSetter {
    input_location: OnceCell<SystemInputLocation>,
    input_struct_location: OnceCell<SystemInputLocation>,
    max_input_size: usize,
}

impl Default for StdNyxInputSetter {
    fn default() -> Self {
        Self {
            input_location: OnceCell::new(),
            input_struct_location: OnceCell::new(),
            max_input_size: 1024 * 1024,
        }
    }
}

pub trait NyxInputSetter<I, S>: InputSetter<I, S> {
    fn set_input_struct_location(
        &mut self,
        location: SystemInputLocation,
    ) -> Result<(), EmulatorDriverError>;

    fn input_struct_location(&self) -> Option<&SystemInputLocation>;

    fn max_input_size(&self) -> usize;
}

impl StdNyxInputSetter {
    pub fn max_input_size(&self) -> usize {
        self.max_input_size
    }
}

impl<I, S> InputSetter<I, S> for StdNyxInputSetter
where
    I: HasTargetBytes,
{
    fn write_input(
        &mut self,
        _qemu: Qemu,
        _state: &mut S,
        input: &I,
    ) -> Result<(), EmulatorDriverError> {
        let input_len =
            i32::try_from(min(self.max_input_size, input.target_bytes().len())).unwrap();

        let kafl_payload = libvharness_sys::kAFL_payload {
            size: input_len,
            ..Default::default()
        };

        let kafl_payload_buf = unsafe {
            from_raw_parts(
                ptr::from_ref(&kafl_payload) as *const u8,
                size_of::<libvharness_sys::kAFL_payload>(),
            )
        };

        // TODO: manage endianness correctly.
        self.input_struct_location
            .get_mut()
            .unwrap()
            .write(kafl_payload_buf);

        // write struct first
        self.input_location
            .get_mut()
            .unwrap()
            .write(input.target_bytes().as_ref());

        Ok(())
    }

    fn set_input_location(
        &mut self,
        location: SystemInputLocation,
    ) -> Result<(), EmulatorDriverError> {
        self.input_location
            .set(location)
            .or(Err(EmulatorDriverError::MultipleInputLocationDefinition))
    }

    fn input_location(&self) -> Option<&SystemInputLocation> {
        self.input_location.get()
    }
}

impl<I, S> NyxInputSetter<I, S> for StdNyxInputSetter
where
    I: HasTargetBytes,
{
    fn set_input_struct_location(
        &mut self,
        location: SystemInputLocation,
    ) -> Result<(), EmulatorDriverError> {
        self.input_struct_location
            .set(location)
            .or(Err(EmulatorDriverError::MultipleInputLocationDefinition))
    }

    fn input_struct_location(&self) -> Option<&SystemInputLocation> {
        self.input_struct_location.get()
    }

    fn max_input_size(&self) -> usize {
        self.max_input_size
    }
}
