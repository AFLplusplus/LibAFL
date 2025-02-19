use libafl::HasMetadata;

use crate::{
    modules::{EmulatorModule, EmulatorModuleTuple, Tracer},
    EmulatorModules, GuestAddr, Hook, Qemu, IS_RCA,
};

#[derive(Debug, Default, Copy, Clone)]
pub struct TracerModule {
    use_rca: bool,
}

impl TracerModule {
    #[must_use]
    pub fn new() -> Self {
        Self { use_rca: false }
    }

    #[must_use]
    pub fn use_rca(&self) -> bool {
        unsafe { IS_RCA }
    }
}

impl<I, S> EmulatorModule<I, S> for TracerModule
where
    I: Unpin,
    S: Unpin + HasMetadata,
{
    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        emulator_modules.reads(
            Hook::Empty,
            Hook::Function(tracer_read::<ET, I, S, 1>),
            Hook::Function(tracer_read::<ET, I, S, 2>),
            Hook::Function(tracer_read::<ET, I, S, 4>),
            Hook::Function(tracer_read::<ET, I, S, 8>),
            Hook::Empty,
        );
    }
}

pub fn tracer_read<ET, I, S, const N: usize>(
    qemu: Qemu,
    _emulator_modules: &mut EmulatorModules<ET, I, S>,
    state: Option<&mut S>,
    _id: u64,
    pc: GuestAddr,
    addr: GuestAddr,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin + HasMetadata,
{
    let is_rca = unsafe { IS_RCA };
    if is_rca {
        let state = state.expect("state missing for rca");
        let predicates = state
            .metadata_mut::<Tracer>()
            .expect("Predicates missing for rca");
        match N {
            1 => {
                let value = unsafe { qemu.read_mem_val::<u8>(addr) };
                if let Ok(value) = value {
                    predicates.update_max_min(pc, u64::from(value));
                }
            }
            2 => {
                let value: Result<u16, crate::QemuRWError> =
                    unsafe { qemu.read_mem_val::<u16>(addr) };
                if let Ok(value) = value {
                    predicates.update_max_min(pc, u64::from(value));
                }
            }
            4 => {
                let value = unsafe { qemu.read_mem_val::<u32>(addr) };
                if let Ok(value) = value {
                    predicates.update_max_min(pc, u64::from(value));
                }
            }
            8 => {
                let value = unsafe { qemu.read_mem_val::<u64>(addr) };
                if let Ok(value) = value {
                    predicates.update_max_min(pc, value);
                }
            }
            _ => {
                unreachable!("Impossible. else you coded it wrong.")
            }
        }
    }
}
