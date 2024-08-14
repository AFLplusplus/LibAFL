use std::{fmt::Debug, marker::PhantomData};

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
    config::QemuConfig,
    modules::{EmulatorModule, EmulatorModuleTuple},
    Emulator, NopEmulatorExitHandler, Qemu, QemuInitError, StdEmulatorExitHandler,
};

#[derive(Clone, Debug)]
enum QemuBuilder {
    Qemu(Qemu),
    QemuConfig(QemuConfig),
    QemuString(Vec<String>),
}

#[derive(Clone, Debug)]
pub struct EmulatorBuilder<CM, EH, ET, S>
where
    S: UsesInput,
{
    modules: ET,
    command_manager: CM,
    exit_handler: EH,
    qemu_builder: Option<QemuBuilder>,
    phantom: PhantomData<S>,
}

impl<S> EmulatorBuilder<NopCommandManager, NopEmulatorExitHandler, (), S>
where
    S: UsesInput,
{
    #[must_use]
    pub fn empty() -> Self {
        Self {
            modules: tuple_list!(),
            command_manager: NopCommandManager,
            exit_handler: NopEmulatorExitHandler,
            qemu_builder: None,
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
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Self {
        let snapshot_manager = { NopSnapshotManager };

        Self {
            modules: (),
            command_manager: StdCommandManager::new(),
            exit_handler: StdEmulatorExitHandler::new(snapshot_manager),
            qemu_builder: None,
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
    S: UsesInput + Unpin,
{
    fn new(
        modules: ET,
        command_manager: CM,
        exit_handler: EH,
        qemu_builder: Option<QemuBuilder>,
    ) -> Self {
        Self {
            modules,
            command_manager,
            exit_handler,
            qemu_builder,
            phantom: PhantomData,
        }
    }

    pub fn build(self) -> Result<Emulator<CM, EH, ET, S>, QemuInitError>
    where
        ET: EmulatorModuleTuple<S>,
    {
        let qemu_builder = self.qemu_builder.ok_or(QemuInitError::EmptyArgs)?;

        let qemu: Qemu = match qemu_builder {
            QemuBuilder::Qemu(qemu) => qemu,
            QemuBuilder::QemuConfig(qemu_config) => {
                let res: Result<Qemu, QemuInitError> = qemu_config.into();
                res?
            }
            QemuBuilder::QemuString(qemu_string) => Qemu::init(&qemu_string)?,
        };

        Emulator::new_with_qemu(qemu, self.modules, self.exit_handler, self.command_manager)
    }
}

impl<CM, EH, ET, S> EmulatorBuilder<CM, EH, ET, S>
where
    S: UsesInput + Unpin,
{
    #[must_use]
    pub fn qemu_config(self, qemu_config: QemuConfig) -> EmulatorBuilder<CM, EH, ET, S> {
        EmulatorBuilder::new(
            self.modules,
            self.command_manager,
            self.exit_handler,
            Some(QemuBuilder::QemuConfig(qemu_config)),
        )
    }

    #[must_use]
    pub fn qemu_cli(self, qemu_cli: Vec<String>) -> EmulatorBuilder<CM, EH, ET, S> {
        EmulatorBuilder::new(
            self.modules,
            self.command_manager,
            self.exit_handler,
            Some(QemuBuilder::QemuString(qemu_cli)),
        )
    }

    #[must_use]
    pub fn qemu(self, qemu: Qemu) -> EmulatorBuilder<CM, EH, ET, S> {
        EmulatorBuilder::new(
            self.modules,
            self.command_manager,
            self.exit_handler,
            Some(QemuBuilder::Qemu(qemu)),
        )
    }

    pub fn prepend_module<EM>(self, module: EM) -> EmulatorBuilder<CM, EH, (EM, ET), S>
    where
        EM: EmulatorModule<S> + Unpin,
    {
        EmulatorBuilder::new(
            self.modules.prepend(module),
            self.command_manager,
            self.exit_handler,
            self.qemu_builder,
        )
    }

    pub fn append_module<EM>(self, module: EM) -> EmulatorBuilder<CM, EH, (ET, EM), S>
    where
        EM: EmulatorModule<S> + Unpin,
        ET: EmulatorModuleTuple<S>,
    {
        EmulatorBuilder::new(
            self.modules.append(module),
            self.command_manager,
            self.exit_handler,
            self.qemu_builder,
        )
    }

    pub fn command_manager<CM2>(self, command_manager: CM2) -> EmulatorBuilder<CM2, EH, ET, S> {
        EmulatorBuilder::new(
            self.modules,
            command_manager,
            self.exit_handler,
            self.qemu_builder,
        )
    }

    pub fn exit_handler<EH2>(self, exit_handler: EH2) -> EmulatorBuilder<CM, EH2, ET, S> {
        EmulatorBuilder::new(
            self.modules,
            self.command_manager,
            exit_handler,
            self.qemu_builder,
        )
    }

    pub fn modules<ET2>(self, modules: ET2) -> EmulatorBuilder<CM, EH, ET2, S> {
        EmulatorBuilder::new(
            modules,
            self.command_manager,
            self.exit_handler,
            self.qemu_builder,
        )
    }
}
