use std::marker::PhantomData;

use libafl::{
    inputs::{HasTargetBytes, UsesInput},
    state::{HasExecutions, State},
};
use libafl_bolts::tuples::{tuple_list, Append, Prepend};

#[cfg(feature = "systemmode")]
use crate::FastSnapshotManager;
use crate::{
    command::{CommandManager, NopCommandManager, StdCommandManager},
    config::QemuConfigBuilder,
    modules::{EmulatorModule, EmulatorModuleTuple},
    Emulator, NopEmulatorDriver, NopSnapshotManager, QemuInitError, QemuParams, StdEmulatorDriver,
    StdSnapshotManager,
};

#[derive(Clone)]
pub struct EmulatorBuilder<CM, ED, ET, QB, S, SM>
where
    S: UsesInput,
{
    modules: ET,
    driver: ED,
    snapshot_manager: SM,
    command_manager: CM,
    qemu_parameters: Option<QB>,
    phantom: PhantomData<S>,
}

impl<S>
    EmulatorBuilder<
        NopCommandManager,
        NopEmulatorDriver,
        (),
        QemuConfigBuilder,
        S,
        NopSnapshotManager,
    >
where
    S: UsesInput,
{
    #[must_use]
    pub fn empty() -> Self {
        Self {
            modules: tuple_list!(),
            driver: NopEmulatorDriver,
            snapshot_manager: NopSnapshotManager,
            command_manager: NopCommandManager,
            qemu_parameters: None,
            phantom: PhantomData,
        }
    }
}

#[cfg(feature = "usermode")]
impl<S>
    EmulatorBuilder<
        StdCommandManager<S>,
        StdEmulatorDriver,
        (),
        QemuConfigBuilder,
        S,
        StdSnapshotManager,
    >
where
    S: State + HasExecutions + Unpin,
    S::Input: HasTargetBytes,
{
    #[must_use]
    #[expect(clippy::should_implement_trait)]
    pub fn default() -> Self {
        Self {
            modules: tuple_list!(),
            command_manager: StdCommandManager::default(),
            snapshot_manager: StdSnapshotManager::default(),
            driver: StdEmulatorDriver::builder().build(),
            qemu_parameters: None,
            phantom: PhantomData,
        }
    }
}

#[cfg(feature = "systemmode")]
impl<S>
    EmulatorBuilder<
        StdCommandManager<S>,
        StdEmulatorDriver,
        (),
        QemuConfigBuilder,
        S,
        StdSnapshotManager,
    >
where
    S: State + HasExecutions + Unpin,
    S::Input: HasTargetBytes,
{
    #[expect(clippy::should_implement_trait)]
    #[must_use]
    pub fn default() -> Self {
        Self {
            modules: (),
            command_manager: StdCommandManager::default(),
            snapshot_manager: FastSnapshotManager::default(),
            driver: StdEmulatorDriver::builder().build(),
            qemu_parameters: None,
            phantom: PhantomData,
        }
    }
}
impl<CM, ED, ET, QP, S, SM> EmulatorBuilder<CM, ED, ET, QP, S, SM>
where
    S: UsesInput + Unpin,
{
    fn new(
        modules: ET,
        driver: ED,
        command_manager: CM,
        snapshot_manager: SM,
        qemu_parameters: Option<QP>,
    ) -> Self {
        Self {
            modules,
            command_manager,
            driver,
            snapshot_manager,
            qemu_parameters,
            phantom: PhantomData,
        }
    }

    pub fn build<E>(self) -> Result<Emulator<CM, ED, ET, S, SM>, QemuInitError>
    where
        CM: CommandManager<ED, ET, S, SM>,
        ET: EmulatorModuleTuple<S>,
        QP: TryInto<QemuParams, Error = E>,
        QemuInitError: From<E>,
    {
        let qemu_params: QemuParams = self
            .qemu_parameters
            .ok_or(QemuInitError::NoParametersProvided)?
            .try_into()?;

        Emulator::new(
            qemu_params,
            self.modules,
            self.driver,
            self.snapshot_manager,
            self.command_manager,
        )
    }
}

impl<CM, ED, ET, QP, S, SM> EmulatorBuilder<CM, ED, ET, QP, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput + Unpin,
{
    #[must_use]
    pub fn qemu_parameters<QB2>(
        self,
        qemu_parameters: QB2,
    ) -> EmulatorBuilder<CM, ED, ET, QB2, S, SM>
    where
        QB2: Into<QemuParams>,
    {
        EmulatorBuilder::new(
            self.modules,
            self.driver,
            self.command_manager,
            self.snapshot_manager,
            Some(qemu_parameters),
        )
    }

    pub fn prepend_module<EM>(self, module: EM) -> EmulatorBuilder<CM, ED, (EM, ET), QP, S, SM>
    where
        EM: EmulatorModule<S> + Unpin,
        ET: EmulatorModuleTuple<S>,
    {
        EmulatorBuilder::new(
            self.modules.prepend(module),
            self.driver,
            self.command_manager,
            self.snapshot_manager,
            self.qemu_parameters,
        )
    }

    pub fn append_module<EM>(self, module: EM) -> EmulatorBuilder<CM, ED, (ET, EM), QP, S, SM>
    where
        EM: EmulatorModule<S> + Unpin,
        ET: EmulatorModuleTuple<S>,
    {
        EmulatorBuilder::new(
            self.modules.append(module),
            self.driver,
            self.command_manager,
            self.snapshot_manager,
            self.qemu_parameters,
        )
    }

    pub fn driver<ED2>(self, driver: ED2) -> EmulatorBuilder<CM, ED2, ET, QP, S, SM> {
        EmulatorBuilder::new(
            self.modules,
            driver,
            self.command_manager,
            self.snapshot_manager,
            self.qemu_parameters,
        )
    }

    pub fn command_manager<CM2>(
        self,
        command_manager: CM2,
    ) -> EmulatorBuilder<CM2, ED, ET, QP, S, SM>
    where
        CM2: CommandManager<ED, ET, S, SM>,
    {
        EmulatorBuilder::new(
            self.modules,
            self.driver,
            command_manager,
            self.snapshot_manager,
            self.qemu_parameters,
        )
    }

    pub fn modules<ET2>(self, modules: ET2) -> EmulatorBuilder<CM, ED, ET2, QP, S, SM> {
        EmulatorBuilder::new(
            modules,
            self.driver,
            self.command_manager,
            self.snapshot_manager,
            self.qemu_parameters,
        )
    }

    pub fn snapshot_manager<SM2>(
        self,
        snapshot_manager: SM2,
    ) -> EmulatorBuilder<CM, ED, ET, QP, S, SM2> {
        EmulatorBuilder::new(
            self.modules,
            self.driver,
            self.command_manager,
            snapshot_manager,
            self.qemu_parameters,
        )
    }
}
