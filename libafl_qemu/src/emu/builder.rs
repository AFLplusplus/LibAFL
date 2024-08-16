use std::{fmt::Debug, marker::PhantomData};

use libafl::{
    inputs::{HasTargetBytes, UsesInput},
    state::{HasExecutions, State},
};
use libafl_bolts::tuples::{tuple_list, Prepend};

#[cfg(emulation_mode = "systemmode")]
use crate::FastSnapshotManager;
use crate::{
    command::{CommandManager, NopCommandManager, StdCommandManager},
    config::QemuConfig,
    modules::{EmulatorModule, EmulatorModuleTuple},
    Emulator, EmulatorDriver, EmulatorDriverTuple, NopSnapshotManager, Qemu, QemuInitError,
    StdEmulatorDriver,
};

#[derive(Clone, Debug)]
enum QemuBuilder {
    Qemu(Qemu),
    QemuConfig(QemuConfig),
    QemuString(Vec<String>),
}

#[derive(Clone, Debug)]
pub struct EmulatorBuilder<CM, EDT, ET, S, SM>
where
    S: UsesInput,
{
    modules: ET,
    drivers: EDT,
    snapshot_manager: SM,
    command_manager: CM,
    qemu_builder: Option<QemuBuilder>,
    phantom: PhantomData<(S, SM)>,
}

impl<S> EmulatorBuilder<NopCommandManager, (), (), S, NopSnapshotManager>
where
    S: UsesInput,
{
    #[must_use]
    pub fn empty() -> Self {
        Self {
            modules: tuple_list!(),
            drivers: tuple_list!(),
            snapshot_manager: NopSnapshotManager,
            command_manager: NopCommandManager,
            qemu_builder: None,
            phantom: PhantomData,
        }
    }
}

#[cfg(emulation_mode = "usermode")]
impl<S> EmulatorBuilder<StdCommandManager<S>, (StdEmulatorDriver, ()), (), S, NopSnapshotManager>
where
    S: State + HasExecutions + Unpin,
    S::Input: HasTargetBytes,
{
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Self {
        Self {
            modules: tuple_list!(),
            command_manager: StdCommandManager::default(),
            snapshot_manager: NopSnapshotManager,
            drivers: tuple_list!(StdEmulatorDriver::default()),
            qemu_builder: None,
            phantom: PhantomData,
        }
    }
}

#[cfg(emulation_mode = "systemmode")]
impl<S> EmulatorBuilder<StdCommandManager<S>, (StdEmulatorDriver, ()), (), S, FastSnapshotManager>
where
    S: State + HasExecutions + Unpin,
    S::Input: HasTargetBytes,
{
    pub fn default() -> Self {
        Self {
            modules: (),
            command_manager: StdCommandManager::default(),
            snapshot_manager: FastSnapshotManager::default(),
            drivers: tuple_list!(StdEmulatorDriver::default()),
            qemu_builder: None,
            phantom: PhantomData,
        }
    }
}
impl<CM, EDT, ET, S, SM> EmulatorBuilder<CM, EDT, ET, S, SM>
where
    CM: CommandManager<S>,
    S: UsesInput + Unpin,
{
    fn new(
        modules: ET,
        drivers: EDT,
        command_manager: CM,
        snapshot_manager: SM,
        qemu_builder: Option<QemuBuilder>,
    ) -> Self {
        Self {
            modules,
            command_manager,
            drivers,
            snapshot_manager,
            qemu_builder,
            phantom: PhantomData,
        }
    }

    pub fn build(self) -> Result<Emulator<CM, EDT, ET, S, SM>, QemuInitError>
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

        Emulator::new_with_qemu(
            qemu,
            self.modules,
            self.drivers,
            self.snapshot_manager,
            self.command_manager,
        )
    }
}

impl<CM, EDT, ET, S, SM> EmulatorBuilder<CM, EDT, ET, S, SM>
where
    CM: CommandManager<S>,
    S: UsesInput + Unpin,
{
    #[must_use]
    pub fn qemu_config(self, qemu_config: QemuConfig) -> EmulatorBuilder<CM, EDT, ET, S, SM> {
        EmulatorBuilder::new(
            self.modules,
            self.drivers,
            self.command_manager,
            self.snapshot_manager,
            Some(QemuBuilder::QemuConfig(qemu_config)),
        )
    }

    #[must_use]
    pub fn qemu_cli(self, qemu_cli: Vec<String>) -> EmulatorBuilder<CM, EDT, ET, S, SM> {
        EmulatorBuilder::new(
            self.modules,
            self.drivers,
            self.command_manager,
            self.snapshot_manager,
            Some(QemuBuilder::QemuString(qemu_cli)),
        )
    }

    #[must_use]
    pub fn qemu(self, qemu: Qemu) -> EmulatorBuilder<CM, EDT, ET, S, SM> {
        EmulatorBuilder::new(
            self.modules,
            self.drivers,
            self.command_manager,
            self.snapshot_manager,
            Some(QemuBuilder::Qemu(qemu)),
        )
    }

    pub fn add_module<EM>(self, module: EM) -> EmulatorBuilder<CM, EDT, (EM, ET), S, SM>
    where
        EM: EmulatorModule<S> + Unpin,
        ET: EmulatorModuleTuple<S>,
    {
        EmulatorBuilder::new(
            self.modules.prepend(module),
            self.drivers,
            self.command_manager,
            self.snapshot_manager,
            self.qemu_builder,
        )
    }

    pub fn add_driver<ED>(self, driver: ED) -> EmulatorBuilder<CM, (ED, EDT), ET, S, SM>
    where
        ED: EmulatorDriver<CM, S, SM>,
        EDT: EmulatorDriverTuple<CM, S, SM>,
    {
        EmulatorBuilder::new(
            self.modules,
            self.drivers.prepend(driver),
            self.command_manager,
            self.snapshot_manager,
            self.qemu_builder,
        )
    }

    pub fn command_manager<CM2>(self, command_manager: CM2) -> EmulatorBuilder<CM2, EDT, ET, S, SM>
    where
        CM2: CommandManager<S>,
    {
        EmulatorBuilder::new(
            self.modules,
            self.drivers,
            command_manager,
            self.snapshot_manager,
            self.qemu_builder,
        )
    }

    pub fn modules<ET2>(self, modules: ET2) -> EmulatorBuilder<CM, EDT, ET2, S, SM> {
        EmulatorBuilder::new(
            modules,
            self.drivers,
            self.command_manager,
            self.snapshot_manager,
            self.qemu_builder,
        )
    }

    pub fn drivers<EDT2>(self, drivers: EDT2) -> EmulatorBuilder<CM, EDT2, ET, S, SM> {
        EmulatorBuilder::new(
            self.modules,
            drivers,
            self.command_manager,
            self.snapshot_manager,
            self.qemu_builder,
        )
    }

    pub fn snapshot_manager<SM2>(
        self,
        snapshot_manager: SM2,
    ) -> EmulatorBuilder<CM, EDT, ET, S, SM2> {
        EmulatorBuilder::new(
            self.modules,
            self.drivers,
            self.command_manager,
            snapshot_manager,
            self.qemu_builder,
        )
    }
}
