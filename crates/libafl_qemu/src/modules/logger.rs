//! Logger Module
//!
//! It's a simple module logging selected events to the logger with the `info` level.
//! It must be built through [`LoggerModuleBuilder`].

use std::fmt::Debug;

use libafl_qemu_sys::TCGTemp;

use crate::{
    EmulatorModules, GuestAddr, Hook, MemAccessInfo,
    modules::{
        EmulatorModule, EmulatorModuleTuple,
        utils::filters::{AddressFilter, NopAddressFilter, NopPageFilter},
    },
    qemu::Qemu,
};

/// A builder for [`LoggerModule`].
///
/// By default, no event is logged.
#[expect(clippy::struct_excessive_bools)]
pub struct LoggerModuleBuilder<AF, PF> {
    calls: bool,
    cmps: bool,
    reads: bool,
    writes: bool,
    threads: bool,
    syscalls: bool,
    custom_insns: bool,
    edges: bool,
    blocks: bool,
    instruction: Option<Vec<GuestAddr>>,

    addr_filter: AF,
    page_filter: PF,
}

impl Default for LoggerModuleBuilder<NopAddressFilter, NopPageFilter> {
    fn default() -> Self {
        Self {
            calls: false,
            cmps: false,
            reads: false,
            writes: false,
            threads: false,
            syscalls: false,
            custom_insns: false,
            edges: false,
            blocks: false,
            instruction: None,
            addr_filter: NopAddressFilter,
            page_filter: NopPageFilter,
        }
    }
}

impl<AF, PF> LoggerModuleBuilder<AF, PF> {
    #[must_use]
    pub fn calls(mut self, calls: bool) -> Self {
        self.calls = calls;

        self
    }

    #[must_use]
    pub fn cmps(mut self, cmps: bool) -> Self {
        self.cmps = cmps;

        self
    }

    #[must_use]
    pub fn reads(mut self, reads: bool) -> Self {
        self.reads = reads;

        self
    }

    #[must_use]
    pub fn writes(mut self, writes: bool) -> Self {
        self.writes = writes;

        self
    }

    #[must_use]
    pub fn threads(mut self, threads: bool) -> Self {
        self.threads = threads;

        self
    }

    #[must_use]
    pub fn syscalls(mut self, syscalls: bool) -> Self {
        self.syscalls = syscalls;

        self
    }

    #[must_use]
    pub fn custom_insns(mut self, custom_insns: bool) -> Self {
        self.custom_insns = custom_insns;

        self
    }

    #[must_use]
    pub fn edges(mut self, edges: bool) -> Self {
        self.edges = edges;

        self
    }

    #[must_use]
    pub fn blocks(mut self, blocks: bool) -> Self {
        self.blocks = blocks;

        self
    }

    #[must_use]
    pub fn instruction(mut self, instruction: GuestAddr) -> Self {
        let instructions = if let Some(insns) = &mut self.instruction {
            insns
        } else {
            self.instruction = Some(Vec::new());

            self.instruction.as_mut().unwrap()
        };

        instructions.push(instruction);

        self
    }

    #[must_use]
    pub fn addr_filter<AF2>(self, addr_filter: AF2) -> LoggerModuleBuilder<AF2, PF> {
        LoggerModuleBuilder {
            calls: self.calls,
            cmps: self.cmps,
            reads: self.reads,
            writes: self.writes,
            threads: self.threads,
            syscalls: self.syscalls,
            custom_insns: self.custom_insns,
            edges: self.edges,
            blocks: self.blocks,
            instruction: self.instruction,
            addr_filter,
            page_filter: self.page_filter,
        }
    }

    #[must_use]
    pub fn page_filter<PF2>(self, page_filter: PF2) -> LoggerModuleBuilder<AF, PF2> {
        LoggerModuleBuilder {
            calls: self.calls,
            cmps: self.cmps,
            reads: self.reads,
            writes: self.writes,
            threads: self.threads,
            syscalls: self.syscalls,
            custom_insns: self.custom_insns,
            edges: self.edges,
            blocks: self.blocks,
            instruction: self.instruction,
            addr_filter: self.addr_filter,
            page_filter,
        }
    }

    #[must_use]
    pub fn build(self) -> LoggerModule<AF, PF> {
        LoggerModule {
            calls: self.calls,
            cmps: self.cmps,
            reads: self.reads,
            writes: self.writes,
            threads: self.threads,
            syscalls: self.syscalls,
            custom_insns: self.custom_insns,
            edges: self.edges,
            blocks: self.blocks,
            instruction: self.instruction,
            addr_filter: self.addr_filter,
            page_filter: self.page_filter,
        }
    }
}

/// Module used to log events in QEMU.
/// It basically logs whatever goes through QEMU's hooks.
/// It can be configured through [`LoggerModuleBuilder`].
#[derive(Debug)]
#[expect(dead_code)]
#[expect(clippy::struct_excessive_bools)]
pub struct LoggerModule<AF, PF> {
    calls: bool,
    cmps: bool,
    reads: bool,
    writes: bool,
    threads: bool,
    syscalls: bool,
    custom_insns: bool,
    edges: bool,
    blocks: bool,
    instruction: Option<Vec<GuestAddr>>,

    addr_filter: AF,
    page_filter: PF,
}

impl LoggerModule<NopAddressFilter, NopPageFilter> {
    #[must_use]
    pub fn builder() -> LoggerModuleBuilder<NopAddressFilter, NopPageFilter> {
        LoggerModuleBuilder::default()
    }
}

#[expect(clippy::unnecessary_wraps)]
fn gen_logger_rw<ET, I, S, const IS_WRITE: bool>(
    _qemu: Qemu,
    _emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
    _addr: *mut TCGTemp,
    info: MemAccessInfo,
) -> Option<u64>
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    let kind = if IS_WRITE { "write" } else { "read" };

    let size = info.size();
    log::info!("[PC {pc:#x}] generator {kind} of {size} bytes");

    Some(0)
}

fn exec_logger_rw<ET, I, S, const IS_WRITE: bool, const N: usize>(
    qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    state: Option<&mut S>,
    id: u64,
    pc: GuestAddr,
    addr: GuestAddr,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    exec_logger_rw_n::<ET, I, S, IS_WRITE>(qemu, emulator_modules, state, id, pc, addr, N);
}

fn exec_logger_rw_n<ET, I, S, const IS_WRITE: bool>(
    _qemu: Qemu,
    _emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    _id: u64,
    pc: GuestAddr,
    addr: GuestAddr,
    size: usize,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    let kind = if IS_WRITE { "write" } else { "read" };

    log::info!("[PC {pc:#x}] exec {kind} of {size} bytes @addr {addr:#x}");
}

impl<AF, I, PF, S> EmulatorModule<I, S> for LoggerModule<AF, PF>
where
    AF: AddressFilter,
    PF: Debug + 'static,
    I: Unpin,
    S: Unpin,
{
    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        if self.reads {
            emulator_modules.reads(
                Hook::Function(gen_logger_rw::<ET, I, S, false>),
                Hook::Function(exec_logger_rw::<ET, I, S, false, 1>),
                Hook::Function(exec_logger_rw::<ET, I, S, false, 2>),
                Hook::Function(exec_logger_rw::<ET, I, S, false, 4>),
                Hook::Function(exec_logger_rw::<ET, I, S, false, 8>),
                Hook::Function(exec_logger_rw_n::<ET, I, S, false>),
            );
        }

        if self.writes {
            emulator_modules.writes(
                Hook::Function(gen_logger_rw::<ET, I, S, true>),
                Hook::Function(exec_logger_rw::<ET, I, S, true, 1>),
                Hook::Function(exec_logger_rw::<ET, I, S, true, 2>),
                Hook::Function(exec_logger_rw::<ET, I, S, true, 4>),
                Hook::Function(exec_logger_rw::<ET, I, S, true, 8>),
                Hook::Function(exec_logger_rw_n::<ET, I, S, true>),
            );
        }

        if self.calls {
            todo!()
        }

        if self.blocks {
            todo!()
        }

        if self.cmps {
            todo!()
        }

        if self.custom_insns {
            todo!()
        }

        if self.edges {
            todo!()
        }

        if self.syscalls {
            todo!()
        }

        if self.threads {
            todo!()
        }

        if self.instruction.is_some() {
            todo!()
        }
    }
}
