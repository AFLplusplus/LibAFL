use std::{
    fmt,
    fmt::{Debug, Display, Formatter},
    ops::Range,
};

use enum_map::Enum;
use libafl::{executors::ExitKind, inputs::HasTargetBytes};
use libafl_qemu_sys::GuestAddr;
#[cfg(feature = "systemmode")]
use libafl_qemu_sys::GuestPhysAddr;
use num_enum::TryFromPrimitive;
use paste::paste;

pub mod parser;
use parser::{
    EndCommandParser, LoadCommandParser, LqprintfCommandParser, SaveCommandParser,
    StartVirtCommandParser, TestCommandParser, VaddrFilterAllowRangeCommandParser,
    VersionCommandParser,
};
#[cfg(feature = "systemmode")]
use parser::{SetMapCommandParser, StartPhysCommandParser};

use super::{CommandError, IsCommand, IsStdCommandManager};
use crate::{
    Emulator, EmulatorDriverError, EmulatorDriverResult, EmulatorExitResult, GenericEmulatorDriver,
    GuestReg, InputLocation, InputSetter, IsSnapshotManager, Regs,
    define_std_command_manager_bound, define_std_command_manager_inner,
    modules::{EmulatorModuleTuple, utils::filters::HasStdFiltersTuple},
};
#[cfg(feature = "systemmode")]
use crate::{MapKind, QemuMemoryChunk};

pub const VERSION_MAJOR: u64 = libvharness_sys::LQEMU_VERSION_MAJOR as u64;
pub const VERSION_MINOR: u64 = libvharness_sys::LQEMU_VERSION_MINOR as u64;

#[cfg(feature = "usermode")]
define_std_command_manager_bound!(
    LqemuCommandManager,
    HasTargetBytes,
    [
        StartCommand,
        SaveCommand,
        LoadCommand,
        EndCommand,
        VersionCommand,
        AddressAllowCommand,
        LqprintfCommand,
        TestCommand
    ],
    [
        StartVirtCommandParser,
        SaveCommandParser,
        LoadCommandParser,
        EndCommandParser,
        VersionCommandParser,
        VaddrFilterAllowRangeCommandParser,
        LqprintfCommandParser,
        TestCommandParser
    ]
);

#[cfg(feature = "systemmode")]
define_std_command_manager_bound!(
    LqemuCommandManager,
    HasTargetBytes,
    [
        StartCommand,
        SaveCommand,
        LoadCommand,
        EndCommand,
        VersionCommand,
        AddressAllowCommand,
        LqprintfCommand,
        TestCommand,
        SetMapCommand
    ],
    [
        StartPhysCommandParser,
        StartVirtCommandParser,
        SaveCommandParser,
        LoadCommandParser,
        EndCommandParser,
        VersionCommandParser,
        VaddrFilterAllowRangeCommandParser,
        LqprintfCommandParser,
        TestCommandParser,
        SetMapCommandParser
    ]
);

#[derive(Debug, Clone, Enum, TryFromPrimitive)]
#[repr(u64)]
pub enum NativeExitKind {
    Unknown = libvharness_sys::LibaflQemuEndStatus_LIBAFL_QEMU_END_UNKNOWN.0 as u64, // Should not be used
    Ok = libvharness_sys::LibaflQemuEndStatus_LIBAFL_QEMU_END_OK.0 as u64,           // Normal exit
    Crash = libvharness_sys::LibaflQemuEndStatus_LIBAFL_QEMU_END_CRASH.0 as u64, // Crash reported in the VM
}

#[derive(Debug, Clone)]
pub struct SaveCommand;
impl<C, CM, ET, I, IS, S, SM> IsCommand<C, CM, GenericEmulatorDriver<IS>, ET, I, S, SM>
    for SaveCommand
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<C, CM, GenericEmulatorDriver<IS>, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        let qemu = emu.qemu();
        let snapshot_id = emu.snapshot_manager_mut().save(qemu);

        emu.driver_mut()
            .set_snapshot_id(snapshot_id)
            .map_err(|_| EmulatorDriverError::MultipleSnapshotDefinition)?;

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct LoadCommand;

impl<C, CM, ET, I, IS, S, SM> IsCommand<C, CM, GenericEmulatorDriver<IS>, ET, I, S, SM>
    for LoadCommand
where
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<C, CM, GenericEmulatorDriver<IS>, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        let qemu = emu.qemu();

        let snapshot_id = emu
            .driver_mut()
            .snapshot_id()
            .ok_or(EmulatorDriverError::SnapshotNotFound)?;

        emu.snapshot_manager_mut().restore(qemu, &snapshot_id)?;

        #[cfg(feature = "paranoid_debug")]
        emu.snapshot_manager_mut().check(qemu, &snapshot_id)?;

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct StartCommand {
    input_location: InputLocation,
}

impl<C, CM, ET, I, IS, S, SM> IsCommand<C, CM, GenericEmulatorDriver<IS>, ET, I, S, SM>
    for StartCommand
where
    CM: IsStdCommandManager,
    ET: EmulatorModuleTuple<I, S> + HasStdFiltersTuple,
    I: HasTargetBytes + Unpin,
    IS: InputSetter<I, S>,
    S: Unpin,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<C, CM, GenericEmulatorDriver<IS>, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        let qemu = emu.qemu();

        if !emu.command_manager_mut().start() {
            // Snapshot VM
            let snapshot_id = emu.snapshot_manager_mut().save(qemu);

            // Set snapshot ID to restore to after fuzzing ends
            emu.driver_mut()
                .set_snapshot_id(snapshot_id)
                .map_err(|_| EmulatorDriverError::MultipleSnapshotDefinition)?;

            // Save input location for next runs
            emu.driver_mut()
                .input_setter_mut()
                .set_input_location(self.input_location.clone())?;

            // Auto page filtering if option is enabled
            #[cfg(feature = "systemmode")]
            if emu.driver_mut().allow_page_on_start() {
                if let Some(paging_id) = qemu.current_cpu().unwrap().current_paging_id() {
                    log::info!("Filter: allow page ID {paging_id}.");
                    emu.modules_mut().modules_mut().allow_page_id_all(paging_id);
                }
            }

            // Make sure JIT cache is empty just before starting
            qemu.flush_jit();

            log::info!("Fuzzing starts @ PC {:x}", qemu.read_reg(Regs::Pc).unwrap());

            return Ok(Some(EmulatorDriverResult::ReturnToClient(
                EmulatorExitResult::FuzzingStarts,
            )));
        }

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct EndCommand {
    exit_kind: Option<ExitKind>,
}

impl<C, ET, I, IS, S, SM>
    IsCommand<C, LqemuCommandManager<S>, GenericEmulatorDriver<IS>, ET, I, S, SM> for EndCommand
where
    ET: EmulatorModuleTuple<I, S>,
    I: HasTargetBytes + Unpin,
    S: Unpin,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<C, LqemuCommandManager<S>, GenericEmulatorDriver<IS>, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        let qemu = emu.qemu();

        if !emu.command_manager_mut().has_started() {
            return Err(EmulatorDriverError::CommandError(
                CommandError::EndBeforeStart,
            ));
        }

        let snapshot_id = emu
            .driver_mut()
            .snapshot_id()
            .ok_or(EmulatorDriverError::SnapshotNotFound)?;

        log::trace!(
            "Restore snapshot @ PC {:x?}",
            qemu.read_reg(Regs::Pc).unwrap()
        );
        emu.snapshot_manager_mut().restore(qemu, &snapshot_id)?;
        log::trace!("PC after restore: {:x?}", qemu.read_reg(Regs::Pc).unwrap());

        #[cfg(feature = "paranoid_debug")]
        emu.snapshot_manager_mut().check(qemu, &snapshot_id)?;

        Ok(Some(EmulatorDriverResult::EndOfRun(
            self.exit_kind.unwrap(),
        )))
    }
}

#[derive(Debug, Clone)]
pub struct VersionCommand(u64, u64);

impl<C, CM, ED, ET, I, S, SM> IsCommand<C, CM, ED, ET, I, S, SM> for VersionCommand {
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &mut Emulator<C, CM, ED, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        let major = self.0;
        let minor = self.1;

        if VERSION_MAJOR == major && VERSION_MINOR == minor {
            Ok(None)
        } else {
            Err(EmulatorDriverError::CommandError(
                CommandError::VersionDifference(major, minor),
            ))
        }
    }
}

#[cfg(feature = "systemmode")]
#[derive(Debug, Clone)]
pub struct PageAllowCommand {
    page_id: GuestPhysAddr,
}

#[cfg(feature = "systemmode")]
impl<C, CM, ED, ET, I, S, SM> IsCommand<C, CM, ED, ET, I, S, SM> for PageAllowCommand
where
    ET: EmulatorModuleTuple<I, S> + HasStdFiltersTuple,
    I: Unpin,
    S: Unpin,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        emu: &mut Emulator<C, CM, ED, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        emu.modules_mut()
            .modules_mut()
            .allow_page_id_all(self.page_id);
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct AddressAllowCommand {
    address_range: Range<GuestAddr>,
}
impl<C, CM, ED, ET, I, S, SM> IsCommand<C, CM, ED, ET, I, S, SM> for AddressAllowCommand
where
    ET: EmulatorModuleTuple<I, S> + HasStdFiltersTuple,
    I: Unpin,
    S: Unpin,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        emu: &mut Emulator<C, CM, ED, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        emu.modules_mut()
            .modules_mut()
            .allow_address_range_all(&self.address_range);
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct LqprintfCommand {
    content: String,
}
impl<C, CM, ED, ET, I, S, SM> IsCommand<C, CM, ED, ET, I, S, SM> for LqprintfCommand
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &mut Emulator<C, CM, ED, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        print!("LQPRINTF: {}", self.content);
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct TestCommand {
    expected_value: GuestReg,
    received_value: GuestReg,
}
impl<C, CM, ED, ET, I, S, SM> IsCommand<C, CM, ED, ET, I, S, SM> for TestCommand
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &mut Emulator<C, CM, ED, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        if self.expected_value == self.received_value {
            Ok(None)
        } else {
            Err(EmulatorDriverError::CommandError(
                CommandError::TestDifference(self.received_value, self.expected_value),
            ))
        }
    }
}

#[cfg(feature = "systemmode")]
#[derive(Debug, Clone)]
pub struct SetMapCommand {
    kind: MapKind,
    map: QemuMemoryChunk,
}

#[cfg(feature = "systemmode")]
impl<C, CM, ET, I, IS, S, SM> IsCommand<C, CM, GenericEmulatorDriver<IS>, ET, I, S, SM>
    for SetMapCommand
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        emu: &mut Emulator<C, CM, GenericEmulatorDriver<IS>, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        let phys_mem_chunk = self
            .map
            .to_phys_mem_chunk(emu.qemu())
            .expect("Declared map is not contiguous in memory");

        assert!(
            emu.driver_mut()
                .maps_mut()
                .insert(self.kind.clone(), phys_mem_chunk)
                .is_none(),
            "a map is being declared two times"
        );

        Ok(None)
    }
}

#[cfg(feature = "systemmode")]
impl SetMapCommand {
    pub fn new(kind: MapKind, map: QemuMemoryChunk) -> Self {
        Self { kind, map }
    }
}

impl TestCommand {
    #[must_use]
    pub fn new(received_value: GuestReg, expected_value: GuestReg) -> Self {
        Self {
            expected_value,
            received_value,
        }
    }
}

impl LqprintfCommand {
    #[must_use]
    pub fn new(content: String) -> Self {
        Self { content }
    }
}

impl VersionCommand {
    #[must_use]
    pub fn new(major: u64, minor: u64) -> Self {
        Self(major, minor)
    }
}

impl AddressAllowCommand {
    #[must_use]
    pub fn new(address_range: Range<GuestAddr>) -> Self {
        Self { address_range }
    }
}

impl Display for SaveCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Save VM")
    }
}

impl Display for LoadCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Reload VM")
    }
}

impl Display for StartCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Start fuzzing with input @{:?}", self.input_location)
    }
}

impl Display for EndCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Exit of kind {:?}", self.exit_kind)
    }
}

impl Display for VersionCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Client version: {}", self.0)
    }
}

impl Display for AddressAllowCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Addr range allow: {:?}", self.address_range)
    }
}

#[cfg(feature = "systemmode")]
impl Display for PageAllowCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Allowed page: {:?}", self.page_id)
    }
}

impl StartCommand {
    #[must_use]
    pub fn new(input_location: InputLocation) -> Self {
        Self { input_location }
    }
}

impl EndCommand {
    #[must_use]
    pub fn new(exit_kind: Option<ExitKind>) -> Self {
        Self { exit_kind }
    }
}
