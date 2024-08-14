use std::marker::PhantomData;

use libafl::{
    inputs::{HasTargetBytes, UsesInput},
    state::{HasExecutions, State},
};
use libafl_bolts::tuples::{tuple_list, Append, Prepend};

#[cfg(emulation_mode = "systemmode")]
use crate::FastSnapshotManager;
#[cfg(emulation_mode = "usermode")]
use crate::NopSnapshotManager;
use crate::{
    command::{NopCommandManager, StdCommandManager},
    modules::{EmulatorModule, EmulatorModuleTuple},
    NopEmulatorExitHandler, StdEmulatorExitHandler,
};

#[derive(Clone, Debug)]
pub struct EmulatorBuilder<CM, EH, ET, S>
where
    S: UsesInput,
{
    modules: ET,
    command_manager: CM,
    exit_handler: EH,
    qemu_cmd: Option<String>,
    phantom: PhantomData<S>,
}

impl<S> EmulatorBuilder<NopCommandManager, NopEmulatorExitHandler, (), S>
where
    S: UsesInput,
{
    pub fn empty() -> Self {
        Self {
            modules: tuple_list!(),
            command_manager: NopCommandManager,
            exit_handler: NopEmulatorExitHandler,
            qemu_cmd: None,
            phantom: PhantomData,
        }
    }
}

#[cfg(emulation_mode = "usermode")]
impl<S>
    EmulatorBuilder<
        StdCommandManager<(), S, NopSnapshotManager>,
        StdEmulatorExitHandler<NopSnapshotManager>,
        (),
        S,
    >
where
    S: State + HasExecutions + Unpin,
    S::Input: HasTargetBytes,
{
    pub fn default() -> Self {
        let snapshot_manager = { NopSnapshotManager };

        Self {
            modules: (),
            command_manager: StdCommandManager::new(),
            exit_handler: StdEmulatorExitHandler::new(snapshot_manager),
            qemu_cmd: None,
            phantom: PhantomData,
        }
    }
}

#[cfg(emulation_mode = "systemmode")]
impl<S>
    EmulatorBuilder<
        StdCommandManager<(), S, FastSnapshotManager>,
        StdEmulatorExitHandler<FastSnapshotManager>,
        (),
        S,
    >
where
    S: State + HasExecutions + Unpin,
    S::Input: HasTargetBytes,
{
    pub fn default() -> Self {
        let snapshot_manager = { FastSnapshotManager::new() };

        Self {
            modules: (),
            command_manager: StdCommandManager::new(),
            exit_handler: StdEmulatorExitHandler::new(snapshot_manager),
            qemu_cmd: None,
            phantom: PhantomData,
        }
    }
}

impl<CM, EH, ET, S> EmulatorBuilder<CM, EH, ET, S>
where
    S: UsesInput,
{
    fn new(modules: ET, command_manager: CM, exit_handler: EH, qemu_cmd: Option<String>) -> Self {
        Self {
            modules,
            command_manager,
            exit_handler,
            qemu_cmd,
            phantom: PhantomData,
        }
    }

    pub fn prepend_module<EM>(self, module: EM) -> EmulatorBuilder<CM, EH, (EM, ET), S>
    where
        EM: EmulatorModule<S> + Unpin,
        S: Unpin,
    {
        EmulatorBuilder::new(
            self.modules.prepend(module),
            self.command_manager,
            self.exit_handler,
            self.qemu_cmd,
        )
    }

    pub fn append_module<EM>(self, module: EM) -> EmulatorBuilder<CM, EH, (ET, EM), S>
    where
        EM: EmulatorModule<S> + Unpin,
        ET: EmulatorModuleTuple<S>,
        S: Unpin,
    {
        EmulatorBuilder::new(
            self.modules.append(module),
            self.command_manager,
            self.exit_handler,
            self.qemu_cmd,
        )
    }

    pub fn command_manager<CM2>(self, command_manager: CM2) -> EmulatorBuilder<CM2, EH, ET, S>
    where
        S: Unpin,
    {
        EmulatorBuilder::new(
            self.modules,
            command_manager,
            self.exit_handler,
            self.qemu_cmd,
        )
    }

    pub fn exit_handler<EH2>(self, exit_handler: EH2) -> EmulatorBuilder<CM, EH2, ET, S>
    where
        S: Unpin,
    {
        EmulatorBuilder::new(
            self.modules,
            self.command_manager,
            exit_handler,
            self.qemu_cmd,
        )
    }

    pub fn modules<ET2>(self, modules: ET2) -> EmulatorBuilder<CM, EH, ET2, S>
    where
        S: Unpin,
    {
        EmulatorBuilder::new(
            modules,
            self.command_manager,
            self.exit_handler,
            self.qemu_cmd,
        )
    }
}
