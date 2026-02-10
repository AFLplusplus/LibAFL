use std::cell::OnceCell;

use libafl::inputs::HasTargetBytes;
use libafl_bolts::AsSlice;

#[cfg(not(all(feature = "systemmode", not(feature = "usermode"))))]
use crate::InputLocation;
#[cfg(all(feature = "systemmode", not(feature = "usermode")))]
use crate::emu::systemmode::SystemInputLocation as InputLocation;
use crate::{GuestReg, Qemu};

#[derive(Debug, Default, Clone)]
pub struct LqemuInputSetter {
    input_location: OnceCell<InputLocation>,
}

impl<I, S> crate::emu::drivers::InputSetter<I, S> for LqemuInputSetter
where
    I: HasTargetBytes,
{
    fn write_input(
        &mut self,
        _qemu: Qemu,
        _state: &mut S,
        input: &I,
    ) -> Result<(), crate::emu::drivers::EmulatorDriverError> {
        if let Some(input_location) = self.input_location.get_mut() {
            let ret_value = input_location.write(input.target_bytes().as_slice());

            if let Some(reg) = input_location.ret_register() {
                input_location
                    .cpu()
                    .write_reg(*reg, ret_value as GuestReg)
                    .unwrap();
            }
        }

        Ok(())
    }

    fn set_input_location(
        &mut self,
        location: InputLocation,
    ) -> Result<(), crate::emu::drivers::EmulatorDriverError> {
        self.input_location.set(location).or(Err(
            crate::emu::drivers::EmulatorDriverError::MultipleInputLocationDefinition,
        ))
    }

    fn input_location(&self) -> Option<&InputLocation> {
        self.input_location.get()
    }
}
