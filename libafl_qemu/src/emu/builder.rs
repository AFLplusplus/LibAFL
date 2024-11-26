use std::{fmt::Debug, marker::PhantomData};

use libafl::{
    inputs::{HasTargetBytes, UsesInput},
    state::{HasExecutions, State},
};
use libafl_bolts::tuples::{tuple_list, Prepend};

#[cfg(feature = "systemmode")]
use crate::FastSnapshotManager;
use crate::{
    command::{CommandManager, NopCommandManager, StdCommandManager},
    config::QemuConfig,
    modules::{EmulatorModule, EmulatorModuleTuple},
    Emulator, EmulatorHooks, EmulatorModules, NopEmulatorDriver, NopSnapshotManager, Qemu,
    QemuHooks, QemuInitError, QemuParams, StdEmulatorDriver, StdSnapshotManager,
};

#[derive(Clone, Debug)]
pub struct EmulatorBuilder<CM, ED, ET, S, SM>
where
    S: UsesInput,
{
    modules: ET,
    driver: ED,
    snapshot_manager: SM,
    command_manager: CM,
    qemu_parameters: Option<QemuParams>,
    phantom: PhantomData<S>,
}

impl<S> EmulatorBuilder<NopCommandManager, NopEmulatorDriver, (), S, NopSnapshotManager>
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
impl<S> EmulatorBuilder<StdCommandManager<S>, StdEmulatorDriver, (), S, StdSnapshotManager>
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
            snapshot_manager: StdSnapshotManager::default(),
            driver: StdEmulatorDriver::builder().build(),
            qemu_parameters: None,
            phantom: PhantomData,
        }
    }
}

#[cfg(feature = "systemmode")]
impl<S> EmulatorBuilder<StdCommandManager<S>, StdEmulatorDriver, (), S, StdSnapshotManager>
where
    S: State + HasExecutions + Unpin,
    S::Input: HasTargetBytes,
{
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
impl<CM, ED, ET, S, SM> EmulatorBuilder<CM, ED, ET, S, SM>
where
    S: UsesInput + Unpin,
{
    fn new(
        modules: ET,
        driver: ED,
        command_manager: CM,
        snapshot_manager: SM,
        qemu_parameters: Option<QemuParams>,
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

    pub fn build(self) -> Result<Emulator<CM, ED, ET, S, SM>, QemuInitError>
    where
        CM: CommandManager<ED, ET, S, SM>,
        ET: EmulatorModuleTuple<S>,
    {
        let qemu_parameters = self.qemu_parameters.ok_or(QemuInitError::EmptyArgs)?;

        let emulator_hooks = unsafe { EmulatorHooks::new(QemuHooks::get_unchecked()) };

        let mut emulator_modules = EmulatorModules::new(emulator_hooks, self.modules);

        // TODO: fix things there properly. The biggest issue being that it creates 2 mut ref to the module with the callback being called
        unsafe {
            emulator_modules
                .modules_mut()
                .pre_qemu_init_all(EmulatorModules::<ET, S>::emulator_modules_mut_unchecked());
        }

        let qemu = Qemu::init(qemu_parameters)?;

        unsafe {
            Ok(Emulator::new_with_qemu(
                qemu,
                emulator_modules,
                self.driver,
                self.snapshot_manager,
                self.command_manager,
            ))
        }
    }
}

impl<CM, ED, ET, S, SM> EmulatorBuilder<CM, ED, ET, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput + Unpin,
{
    #[must_use]
    pub fn qemu_config(self, qemu_config: QemuConfig) -> EmulatorBuilder<CM, ED, ET, S, SM> {
        EmulatorBuilder::new(
            self.modules,
            self.driver,
            self.command_manager,
            self.snapshot_manager,
            Some(QemuParams::Config(qemu_config)),
        )
    }

    #[must_use]
    pub fn qemu_cli(self, qemu_cli: Vec<String>) -> EmulatorBuilder<CM, ED, ET, S, SM> {
        EmulatorBuilder::new(
            self.modules,
            self.driver,
            self.command_manager,
            self.snapshot_manager,
            Some(QemuParams::Cli(qemu_cli)),
        )
    }

    pub fn add_module<EM>(self, module: EM) -> EmulatorBuilder<CM, ED, (EM, ET), S, SM>
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

    pub fn driver<ED2>(self, driver: ED2) -> EmulatorBuilder<CM, ED2, ET, S, SM> {
        EmulatorBuilder::new(
            self.modules,
            driver,
            self.command_manager,
            self.snapshot_manager,
            self.qemu_parameters,
        )
    }

    pub fn command_manager<CM2>(self, command_manager: CM2) -> EmulatorBuilder<CM2, ED, ET, S, SM>
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

    pub fn modules<ET2>(self, modules: ET2) -> EmulatorBuilder<CM, ED, ET2, S, SM> {
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
    ) -> EmulatorBuilder<CM, ED, ET, S, SM2> {
        EmulatorBuilder::new(
            self.modules,
            self.driver,
            self.command_manager,
            snapshot_manager,
            self.qemu_parameters,
        )
    }
}
