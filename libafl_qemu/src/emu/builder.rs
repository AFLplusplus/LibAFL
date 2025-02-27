use std::marker::PhantomData;

use libafl::{inputs::HasTargetBytes, state::HasExecutions};
use libafl_bolts::tuples::{Append, Prepend, tuple_list};

#[cfg(feature = "systemmode")]
use crate::FastSnapshotManager;
use crate::{
    Emulator, NopEmulatorDriver, NopSnapshotManager, QemuInitError, QemuParams, StdEmulatorDriver,
    StdSnapshotManager,
    command::{NopCommandManager, StdCommandManager},
    config::QemuConfigBuilder,
    modules::{EmulatorModule, EmulatorModuleTuple},
};
#[cfg(doc)]
use crate::{Qemu, config::QemuConfig};

/// An [`Emulator`] Builder.
///
/// It is the most common way to create a new [`Emulator`].
/// In addition to the main components of an [`Emulator`], it expects to receive a way to initialize [`Qemu`].
/// It must be set through [`EmulatorBuilder::qemu_parameters`].
/// At the moment, there are two main ways to initialize QEMU:
/// - with a QEMU-compatible CLI. It will be given to QEMU as-is. The first argument should always be a path to the running binary, as expected by execve.
/// - with an instance of [`QemuConfig`]. It is a more programmatic way to configure [`Qemu`]. It should be built using [`QemuConfigBuilder`].
#[derive(Clone)]
pub struct EmulatorBuilder<C, CM, ED, ET, QP, I, S, SM> {
    modules: ET,
    driver: ED,
    snapshot_manager: SM,
    command_manager: CM,
    qemu_parameters: Option<QP>,
    phantom: PhantomData<(C, I, S)>,
}

impl<C, I, S>
    EmulatorBuilder<
        C,
        NopCommandManager,
        NopEmulatorDriver,
        (),
        QemuConfigBuilder,
        I,
        S,
        NopSnapshotManager,
    >
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
impl<C, I, S>
    EmulatorBuilder<
        C,
        StdCommandManager<S>,
        StdEmulatorDriver,
        (),
        QemuConfigBuilder,
        I,
        S,
        StdSnapshotManager,
    >
where
    S: HasExecutions + Unpin,
    I: HasTargetBytes,
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
impl<C, I, S>
    EmulatorBuilder<
        C,
        StdCommandManager<S>,
        StdEmulatorDriver,
        (),
        QemuConfigBuilder,
        I,
        S,
        StdSnapshotManager,
    >
where
    S: HasExecutions + Unpin,
    I: HasTargetBytes,
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
impl<C, CM, ED, ET, QP, I, S, SM> EmulatorBuilder<C, CM, ED, ET, QP, I, S, SM>
where
    I: Unpin,
    S: Unpin,
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

    #[allow(clippy::type_complexity)]
    pub fn build<E>(self) -> Result<Emulator<C, CM, ED, ET, I, S, SM>, QemuInitError>
    where
        ET: EmulatorModuleTuple<I, S>,
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

impl<C, CM, ED, ET, QP, I, S, SM> EmulatorBuilder<C, CM, ED, ET, QP, I, S, SM>
where
    I: Unpin,
    S: Unpin,
{
    #[must_use]
    pub fn qemu_parameters<QP2>(
        self,
        qemu_parameters: QP2,
    ) -> EmulatorBuilder<C, CM, ED, ET, QP2, I, S, SM>
    where
        QP2: Into<QemuParams>,
    {
        EmulatorBuilder::new(
            self.modules,
            self.driver,
            self.command_manager,
            self.snapshot_manager,
            Some(qemu_parameters),
        )
    }

    pub fn prepend_module<EM>(
        self,
        module: EM,
    ) -> EmulatorBuilder<C, CM, ED, (EM, ET), QP, I, S, SM>
    where
        EM: EmulatorModule<I, S> + Unpin,
        ET: EmulatorModuleTuple<I, S>,
    {
        EmulatorBuilder::new(
            self.modules.prepend(module),
            self.driver,
            self.command_manager,
            self.snapshot_manager,
            self.qemu_parameters,
        )
    }

    pub fn append_module<EM>(self, module: EM) -> EmulatorBuilder<C, CM, ED, (ET, EM), QP, I, S, SM>
    where
        EM: EmulatorModule<I, S> + Unpin,
        ET: EmulatorModuleTuple<I, S>,
    {
        EmulatorBuilder::new(
            self.modules.append(module),
            self.driver,
            self.command_manager,
            self.snapshot_manager,
            self.qemu_parameters,
        )
    }

    pub fn driver<ED2>(self, driver: ED2) -> EmulatorBuilder<C, CM, ED2, ET, QP, I, S, SM> {
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
    ) -> EmulatorBuilder<C, CM2, ED, ET, QP, I, S, SM> {
        EmulatorBuilder::new(
            self.modules,
            self.driver,
            command_manager,
            self.snapshot_manager,
            self.qemu_parameters,
        )
    }

    pub fn modules<ET2>(self, modules: ET2) -> EmulatorBuilder<C, CM, ED, ET2, QP, I, S, SM> {
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
    ) -> EmulatorBuilder<C, CM, ED, ET, QP, I, S, SM2> {
        EmulatorBuilder::new(
            self.modules,
            self.driver,
            self.command_manager,
            snapshot_manager,
            self.qemu_parameters,
        )
    }
}
