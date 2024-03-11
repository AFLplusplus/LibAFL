#[cfg(emulation_mode = "systemmode")]
use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};

use enum_map::Enum;
use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    executors::ExitKind,
    inputs::{BytesInput, HasBytesVec},
    state::StdState,
};
use libafl_bolts::rands::RomuDuoJrRand;
use num_enum::TryFromPrimitive;

#[cfg(emulation_mode = "systemmode")]
use crate::QemuInstrumentationPagingFilter;
use crate::{
    get_qemu_hooks, sync_backdoor::SyncBackdoorError, Emulator, GuestAddrKind, GuestPhysAddr,
    GuestReg, GuestVirtAddr, HandlerError, HasInstrumentationFilter, InnerHandlerResult,
    IsEmuExitHandler, IsFilter, IsSnapshotManager, QemuEdgeCoverageHelper, QemuHooks,
    QemuInstrumentationAddressRangeFilter, Regs, StdEmuExitHandler, CPU,
};

pub const VERSION: u64 = bindings::LIBAFL_EXIT_VERSION_NUMBER as u64;

mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(improper_ctypes)]
    #![allow(unused_mut)]
    #![allow(unused)]
    #![allow(unused_variables)]
    #![allow(clippy::all)]
    #![allow(clippy::pedantic)]

    include!(concat!(env!("OUT_DIR"), "/backdoor_bindings.rs"));
}

#[derive(Debug, Clone, TryFromPrimitive)]
#[repr(u64)]
pub enum NativeBackdoorCommand {
    StartVirt = bindings::LibaflExit_LIBAFL_EXIT_START_VIRT.0 as u64, // Shortcut for Save + InputVirt
    StartPhys = bindings::LibaflExit_LIBAFL_EXIT_START_PHYS.0 as u64, // Shortcut for Save + InputPhys
    InputVirt = bindings::LibaflExit_LIBAFL_EXIT_INPUT_VIRT.0 as u64, // The address is a virtual address using the paging currently running in the VM.
    InputPhys = bindings::LibaflExit_LIBAFL_EXIT_INPUT_PHYS.0 as u64, // The address is a physical address
    End = bindings::LibaflExit_LIBAFL_EXIT_END.0 as u64, // Implies reloading of the target. The first argument gives the exit status.
    Save = bindings::LibaflExit_LIBAFL_EXIT_SAVE.0 as u64, // Save the VM
    Load = bindings::LibaflExit_LIBAFL_EXIT_LOAD.0 as u64, // Reload the target without ending the run?
    Version = bindings::LibaflExit_LIBAFL_EXIT_VERSION.0 as u64, // Version of the bindings used in the target
    VaddrFilterAllowRange = bindings::LibaflExit_LIBAFL_EXIT_VADDR_FILTER_ALLOW.0 as u64, // Allow given address range
}

#[derive(Debug, Clone, Enum, TryFromPrimitive)]
#[repr(u64)]
pub enum NativeExitKind {
    Unknown = bindings::LibaflExitEndStatus_LIBAFL_EXIT_END_UNKNOWN.0 as u64, // Should not be used
    Ok = bindings::LibaflExitEndStatus_LIBAFL_EXIT_END_OK.0 as u64,           // Normal exit
    Crash = bindings::LibaflExitEndStatus_LIBAFL_EXIT_END_CRASH.0 as u64, // Crash reported in the VM
}

pub trait IsCommand<E>
where
    E: IsEmuExitHandler,
{
    /// Used to know whether the command can be run during a backdoor, or if it is necessary to go out of
    /// the QEMU VM to run the command.
    fn usable_at_runtime(&self) -> bool;

    /// Command handler.
    ///     - `input`: The input for the current emulator run.
    ///     - `ret_reg`: The register in which the guest return value should be written, if any.
    /// Returns
    ///     - `InnerHandlerResult`: How the high-level handler should behave
    fn run(
        &self,
        emu: &Emulator<E>,
        emu_exit_handler: &mut E,
        input: &BytesInput,
        ret_reg: Option<Regs>,
    ) -> Result<InnerHandlerResult, HandlerError>;
}

#[cfg(emulation_mode = "systemmode")]
pub type PagingFilterCommand = FilterCommand<QemuInstrumentationPagingFilter>;

pub type AddressRangeFilterCommand = FilterCommand<QemuInstrumentationAddressRangeFilter>;

#[derive(Debug, Clone)]
pub enum Command {
    SaveCommand(SaveCommand),
    LoadCommand(LoadCommand),
    InputCommand(InputCommand),
    StartCommand(StartCommand),
    EndCommand(EndCommand),
    VersionCommand(VersionCommand),
    #[cfg(emulation_mode = "systemmode")]
    PagingFilterCommand(PagingFilterCommand),
    AddressRangeFilterCommand(AddressRangeFilterCommand),
}

// TODO: Replace with enum_dispatch implementation
impl<SM> IsCommand<StdEmuExitHandler<SM>> for Command
where
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        match self {
            Command::SaveCommand(cmd) => {
                <SaveCommand as IsCommand<StdEmuExitHandler<SM>>>::usable_at_runtime(cmd)
            }
            Command::LoadCommand(cmd) => {
                <LoadCommand as IsCommand<StdEmuExitHandler<SM>>>::usable_at_runtime(cmd)
            }
            Command::InputCommand(cmd) => {
                <InputCommand as IsCommand<StdEmuExitHandler<SM>>>::usable_at_runtime(cmd)
            }
            Command::StartCommand(cmd) => {
                <StartCommand as IsCommand<StdEmuExitHandler<SM>>>::usable_at_runtime(cmd)
            }
            Command::EndCommand(cmd) => {
                <EndCommand as IsCommand<StdEmuExitHandler<SM>>>::usable_at_runtime(cmd)
            }
            Command::VersionCommand(cmd) => {
                <VersionCommand as IsCommand<StdEmuExitHandler<SM>>>::usable_at_runtime(cmd)
            }
            #[cfg(emulation_mode = "systemmode")]
            Command::PagingFilterCommand(cmd) => {
                <PagingFilterCommand as IsCommand<StdEmuExitHandler<SM>>>::usable_at_runtime(cmd)
            }
            Command::AddressRangeFilterCommand(cmd) => <AddressRangeFilterCommand as IsCommand<
                StdEmuExitHandler<SM>,
            >>::usable_at_runtime(cmd),
        }
    }

    fn run(
        &self,
        emu: &Emulator<StdEmuExitHandler<SM>>,
        emu_exit_handler: &mut StdEmuExitHandler<SM>,
        input: &BytesInput,
        ret_reg: Option<Regs>,
    ) -> Result<InnerHandlerResult, HandlerError> {
        match self {
            Command::SaveCommand(cmd) => <SaveCommand as IsCommand<StdEmuExitHandler<SM>>>::run(
                cmd,
                emu,
                emu_exit_handler,
                input,
                ret_reg,
            ),
            Command::LoadCommand(cmd) => <LoadCommand as IsCommand<StdEmuExitHandler<SM>>>::run(
                cmd,
                emu,
                emu_exit_handler,
                input,
                ret_reg,
            ),
            Command::InputCommand(cmd) => <InputCommand as IsCommand<StdEmuExitHandler<SM>>>::run(
                cmd,
                emu,
                emu_exit_handler,
                input,
                ret_reg,
            ),
            Command::StartCommand(cmd) => <StartCommand as IsCommand<StdEmuExitHandler<SM>>>::run(
                cmd,
                emu,
                emu_exit_handler,
                input,
                ret_reg,
            ),
            Command::EndCommand(cmd) => <EndCommand as IsCommand<StdEmuExitHandler<SM>>>::run(
                cmd,
                emu,
                emu_exit_handler,
                input,
                ret_reg,
            ),
            Command::VersionCommand(cmd) => {
                <VersionCommand as IsCommand<StdEmuExitHandler<SM>>>::run(
                    cmd,
                    emu,
                    emu_exit_handler,
                    input,
                    ret_reg,
                )
            }
            #[cfg(emulation_mode = "systemmode")]
            Command::PagingFilterCommand(cmd) => <PagingFilterCommand as IsCommand<
                StdEmuExitHandler<SM>,
            >>::run(
                cmd, emu, emu_exit_handler, input, ret_reg
            ),
            Command::AddressRangeFilterCommand(cmd) => <AddressRangeFilterCommand as IsCommand<
                StdEmuExitHandler<SM>,
            >>::run(
                cmd, emu, emu_exit_handler, input, ret_reg
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EmulatorMemoryChunk {
    addr: GuestAddrKind,
    size: GuestReg,
    cpu: Option<CPU>,
}

#[derive(Debug, Clone)]
pub struct SaveCommand;

impl<SM> IsCommand<StdEmuExitHandler<SM>> for SaveCommand
where
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &Emulator<StdEmuExitHandler<SM>>,
        emu_exit_handler: &mut StdEmuExitHandler<SM>,
        _input: &BytesInput,
        _ret_reg: Option<Regs>,
    ) -> Result<InnerHandlerResult, HandlerError> {
        let snapshot_id = emu_exit_handler.snapshot_manager_mut().save(emu);
        emu_exit_handler.snapshot_id().set(snapshot_id).unwrap();

        // TODO: get helpers from harness cleanly. Find a way to use generics without trait overflow.
        #[cfg(emulation_mode = "systemmode")]
        {
            let qemu_helpers: &mut QemuHooks<
                (QemuEdgeCoverageHelper, ()),
                StdState<
                    BytesInput,
                    InMemoryCorpus<BytesInput>,
                    RomuDuoJrRand,
                    OnDiskCorpus<BytesInput>,
                >,
                StdEmuExitHandler<SM>,
            > = unsafe {
                get_qemu_hooks::<
                    (QemuEdgeCoverageHelper, ()),
                    StdState<
                        BytesInput,
                        InMemoryCorpus<BytesInput>,
                        RomuDuoJrRand,
                        OnDiskCorpus<BytesInput>,
                    >,
                    StdEmuExitHandler<SM>,
                >()
            };

            // TODO: Improve this part used to perform paging filtering
            let helpers = qemu_helpers.helpers_mut();

            let mut allowed_paging_ids = HashSet::new();

            let current_paging_id = emu.current_cpu().unwrap().get_current_paging_id().unwrap();
            allowed_paging_ids.insert(current_paging_id);

            let paging_filter =
                HasInstrumentationFilter::<QemuInstrumentationPagingFilter>::filter_mut(helpers);

            *paging_filter = QemuInstrumentationPagingFilter::AllowList(allowed_paging_ids);
        }

        Ok(InnerHandlerResult::Continue)
    }
}

#[derive(Debug, Clone)]
pub struct LoadCommand;

impl<SM> IsCommand<StdEmuExitHandler<SM>> for LoadCommand
where
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &Emulator<StdEmuExitHandler<SM>>,
        emu_exit_handler: &mut StdEmuExitHandler<SM>,
        _input: &BytesInput,
        _ret_reg: Option<Regs>,
    ) -> Result<InnerHandlerResult, HandlerError> {
        let snapshot_id = *emu_exit_handler
            .snapshot_id()
            .get()
            .ok_or(HandlerError::SnapshotNotFound)?;

        emu_exit_handler
            .snapshot_manager_mut()
            .restore(&snapshot_id, emu)?;

        Ok(InnerHandlerResult::Continue)
    }
}

#[derive(Debug, Clone)]
pub struct InputCommand {
    location: EmulatorMemoryChunk,
}

impl<SM> IsCommand<StdEmuExitHandler<SM>> for InputCommand
where
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        emu: &Emulator<StdEmuExitHandler<SM>>,
        _emu_exit_handler: &mut StdEmuExitHandler<SM>,
        input: &BytesInput,
        ret_reg: Option<Regs>,
    ) -> Result<InnerHandlerResult, HandlerError> {
        let ret_value = self.location.write(emu, input.bytes());

        if let Some(reg) = ret_reg {
            emu.write_reg(reg, ret_value).unwrap();
        }

        Ok(InnerHandlerResult::Continue)
    }
}

#[derive(Debug, Clone)]
pub struct StartCommand {
    input_location: EmulatorMemoryChunk,
}

impl<SM> IsCommand<StdEmuExitHandler<SM>> for StartCommand
where
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &Emulator<StdEmuExitHandler<SM>>,
        emu_exit_handler: &mut StdEmuExitHandler<SM>,
        input: &BytesInput,
        ret_reg: Option<Regs>,
    ) -> Result<InnerHandlerResult, HandlerError> {
        let snapshot_id = emu_exit_handler.snapshot_manager_mut().save(emu);

        emu_exit_handler
            .snapshot_id()
            .set(snapshot_id)
            .map_err(|_| HandlerError::MultipleSnapshotDefinition)?;

        emu_exit_handler
            .set_input_location(self.input_location.clone(), ret_reg)
            .unwrap();

        let ret_value = self.input_location.write(emu, input.bytes());

        if let Some(reg) = ret_reg {
            emu.write_reg(reg, ret_value).unwrap();
        }

        Ok(InnerHandlerResult::Continue)
    }
}

#[derive(Debug, Clone)]
pub struct EndCommand(Option<ExitKind>);

impl<SM> IsCommand<StdEmuExitHandler<SM>> for EndCommand
where
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &Emulator<StdEmuExitHandler<SM>>,
        emu_exit_handler: &mut StdEmuExitHandler<SM>,
        _input: &BytesInput,
        _ret_reg: Option<Regs>,
    ) -> Result<InnerHandlerResult, HandlerError> {
        let snapshot_id = *emu_exit_handler
            .snapshot_id()
            .get()
            .ok_or(HandlerError::SnapshotNotFound)?;

        emu_exit_handler
            .snapshot_manager_mut()
            .restore(&snapshot_id, emu)?;

        Ok(InnerHandlerResult::EndOfRun(self.0.unwrap()))
    }
}

#[derive(Debug, Clone)]
pub struct VersionCommand(u64);

impl<SM> IsCommand<StdEmuExitHandler<SM>> for VersionCommand
where
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &Emulator<StdEmuExitHandler<SM>>,
        _emu_exit_handler: &mut StdEmuExitHandler<SM>,
        _input: &BytesInput,
        _ret_reg: Option<Regs>,
    ) -> Result<InnerHandlerResult, HandlerError> {
        let guest_version = self.0;

        if VERSION == guest_version {
            Ok(InnerHandlerResult::Continue)
        } else {
            Err(HandlerError::SyncBackdoorError(
                SyncBackdoorError::VersionDifference(guest_version),
            ))
        }
    }
}

#[derive(Debug, Clone)]
pub struct FilterCommand<T>
where
    T: IsFilter + Debug,
{
    filter: T,
}

#[cfg(emulation_mode = "systemmode")]
impl<SM> IsCommand<StdEmuExitHandler<SM>> for PagingFilterCommand
where
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &Emulator<StdEmuExitHandler<SM>>,
        _emu_exit_handler: &mut StdEmuExitHandler<SM>,
        _input: &BytesInput,
        _ret_reg: Option<Regs>,
    ) -> Result<InnerHandlerResult, HandlerError> {
        // TODO: get helpers from harness cleanly. Find a way to use generics without trait overflow.
        let qemu_helpers: &mut QemuHooks<
            (QemuEdgeCoverageHelper, ()),
            StdState<
                BytesInput,
                InMemoryCorpus<BytesInput>,
                RomuDuoJrRand,
                OnDiskCorpus<BytesInput>,
            >,
            StdEmuExitHandler<SM>,
        > = unsafe {
            get_qemu_hooks::<
                (QemuEdgeCoverageHelper, ()),
                StdState<
                    BytesInput,
                    InMemoryCorpus<BytesInput>,
                    RomuDuoJrRand,
                    OnDiskCorpus<BytesInput>,
                >,
                StdEmuExitHandler<SM>,
            >()
        };

        // TODO: Improve this part used to perform addr filtering
        let helpers = qemu_helpers.helpers_mut();

        let paging_filter =
            HasInstrumentationFilter::<QemuInstrumentationPagingFilter>::filter_mut(helpers);

        *paging_filter = self.filter.clone();

        Ok(InnerHandlerResult::Continue)
    }
}

impl<SM> IsCommand<StdEmuExitHandler<SM>> for AddressRangeFilterCommand
where
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    #[allow(clippy::type_complexity)] // TODO: refactor with correct type.
    fn run(
        &self,
        _emu: &Emulator<StdEmuExitHandler<SM>>,
        _emu_exit_handler: &mut StdEmuExitHandler<SM>,
        _input: &BytesInput,
        _ret_reg: Option<Regs>,
    ) -> Result<InnerHandlerResult, HandlerError> {
        // TODO: get helpers from harness cleanly. Find a way to use generics without trait overflow.
        let qemu_helpers: &mut QemuHooks<
            (QemuEdgeCoverageHelper, ()),
            StdState<
                BytesInput,
                InMemoryCorpus<BytesInput>,
                RomuDuoJrRand,
                OnDiskCorpus<BytesInput>,
            >,
            StdEmuExitHandler<SM>,
        > = unsafe {
            get_qemu_hooks::<
                (QemuEdgeCoverageHelper, ()),
                StdState<
                    BytesInput,
                    InMemoryCorpus<BytesInput>,
                    RomuDuoJrRand,
                    OnDiskCorpus<BytesInput>,
                >,
                StdEmuExitHandler<SM>,
            >()
        };

        // TODO: Improve this part used to perform addr filtering
        let helpers = qemu_helpers.helpers_mut();

        let addr_range_filter =
            HasInstrumentationFilter::<QemuInstrumentationAddressRangeFilter>::filter_mut(helpers);

        *addr_range_filter = self.filter.clone();

        Ok(InnerHandlerResult::Continue)
    }
}

impl VersionCommand {
    #[must_use]
    pub fn new(version: u64) -> Self {
        Self(version)
    }
}

impl<T> FilterCommand<T>
where
    T: IsFilter + Debug,
{
    pub fn new(filter: T) -> Self {
        Self { filter }
    }
}

// TODO: rewrite with display implementation for each command.
impl Display for Command {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::SaveCommand(_) => write!(f, "Save VM"),
            Command::LoadCommand(_) => write!(f, "Reload VM"),
            Command::InputCommand(input_command) => {
                write!(f, "Set fuzzing input @{}", input_command.location.addr)
            }
            Command::StartCommand(start_command) => {
                write!(
                    f,
                    "Start fuzzing with input @{}",
                    start_command.input_location.addr
                )
            }
            Command::EndCommand(end_command) => write!(f, "Exit of kind {:?}", end_command.0),
            Command::VersionCommand(version_command) => {
                write!(f, "Client version: {}", version_command.0)
            }
            Command::AddressRangeFilterCommand(addr_range_filter) => {
                write!(f, "Addr range filter: {:?}", addr_range_filter.filter,)
            }
            #[cfg(emulation_mode = "systemmode")]
            Command::PagingFilterCommand(paging_filter) => {
                write!(f, "Addr range filter: {:?}", paging_filter.filter,)
            }
        }
    }
}

impl StartCommand {
    #[must_use]
    pub fn new(input_location: EmulatorMemoryChunk) -> Self {
        Self { input_location }
    }
}

impl EndCommand {
    #[must_use]
    pub fn new(exit_kind: Option<ExitKind>) -> Self {
        Self(exit_kind)
    }
}

impl InputCommand {
    #[must_use]
    pub fn new(location: EmulatorMemoryChunk) -> Self {
        Self { location }
    }
}

impl EmulatorMemoryChunk {
    #[must_use]
    pub fn phys(addr: GuestPhysAddr, size: GuestReg, cpu: Option<CPU>) -> Self {
        Self {
            addr: GuestAddrKind::Physical(addr),
            size,
            cpu,
        }
    }

    #[must_use]
    pub fn virt(addr: GuestVirtAddr, size: GuestReg, cpu: CPU) -> Self {
        Self {
            addr: GuestAddrKind::Virtual(addr),
            size,
            cpu: Some(cpu),
        }
    }

    /// Returns the number of bytes effectively written.
    #[must_use]
    pub fn write<E>(&self, emu: &Emulator<E>, input: &[u8]) -> GuestReg
    where
        E: IsEmuExitHandler,
    {
        let max_len: usize = self.size.try_into().unwrap();

        let input_sliced = if input.len() > max_len {
            &input[0..max_len]
        } else {
            input
        };

        match self.addr {
            GuestAddrKind::Physical(hwaddr) => unsafe {
                #[cfg(emulation_mode = "usermode")]
                {
                    // For now the default behaviour is to fall back to virtual addresses
                    emu.write_mem(hwaddr.try_into().unwrap(), input_sliced);
                }
                #[cfg(emulation_mode = "systemmode")]
                {
                    emu.write_phys_mem(hwaddr, input_sliced);
                }
            },
            GuestAddrKind::Virtual(vaddr) => unsafe {
                self.cpu
                    .as_ref()
                    .unwrap()
                    .write_mem(vaddr.try_into().unwrap(), input_sliced);
            },
        };

        input_sliced.len().try_into().unwrap()
    }
}

impl Display for InputCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (0x{:x} max nb bytes)",
            self.location.addr, self.location.size
        )
    }
}
