use std::fmt::Debug;

use crate::modules::{EmulatorModule, EmulatorModuleTuple};

#[derive(Debug)]
pub struct OptionalModule<MD> {
    enabled: bool,
    module: MD,
}

impl<MD> OptionalModule<MD> {
    pub fn new(enabled: bool, module: MD) -> Self {
        Self { enabled, module }
    }

    pub fn get_inner_module_mut(&mut self) -> &mut MD {
        &mut self.module
    }
}

impl<MD, I, S> EmulatorModule<I, S> for OptionalModule<MD>
where
    I: Unpin,
    S: Unpin,
    MD: EmulatorModule<I, S>,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = true;

    fn pre_qemu_init<ET>(
        &mut self,
        emulator_modules: &mut crate::EmulatorModules<ET, I, S>,
        qemu_params: &mut crate::QemuParams,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        if self.enabled {
            self.module.pre_qemu_init(emulator_modules, qemu_params);
        }
    }

    fn post_qemu_init<ET>(
        &mut self,
        qemu: crate::Qemu,
        emulator_modules: &mut crate::EmulatorModules<ET, I, S>,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        if self.enabled {
            self.module.post_qemu_init(qemu, emulator_modules);
        }
    }

    fn first_exec<ET>(
        &mut self,
        qemu: crate::Qemu,
        emulator_modules: &mut crate::EmulatorModules<ET, I, S>,
        state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        if self.enabled {
            self.module.first_exec(qemu, emulator_modules, state);
        }
    }

    fn pre_exec<ET>(
        &mut self,
        qemu: crate::Qemu,
        emulator_modules: &mut crate::EmulatorModules<ET, I, S>,
        state: &mut S,
        input: &I,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        if self.enabled {
            self.module.pre_exec(qemu, emulator_modules, state, input);
        }
    }

    fn post_exec<OT, ET>(
        &mut self,
        qemu: crate::Qemu,
        emulator_modules: &mut crate::EmulatorModules<ET, I, S>,
        state: &mut S,
        input: &I,
        observers: &mut OT,
        exit_kind: &mut libafl::executors::ExitKind,
    ) where
        OT: libafl::observers::ObserversTuple<I, S>,
        ET: EmulatorModuleTuple<I, S>,
    {
        if self.enabled {
            self.module
                .post_exec(qemu, emulator_modules, state, input, observers, exit_kind);
        }
    }

    unsafe fn on_crash(&mut self) {
        if self.enabled {
            unsafe {
                self.module.on_crash();
            }
        }
    }

    unsafe fn on_timeout(&mut self) {
        if self.enabled {
            unsafe {
                self.module.on_timeout();
            }
        }
    }
}
