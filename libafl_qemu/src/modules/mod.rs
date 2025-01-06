use core::{fmt::Debug, ops::Range};

use libafl::{executors::ExitKind, inputs::UsesInput, observers::ObserversTuple};
use libafl_bolts::tuples::{MatchFirstType, SplitBorrowExtractFirstType};
use libafl_qemu_sys::GuestAddr;
#[cfg(feature = "systemmode")]
use libafl_qemu_sys::GuestPhysAddr;

use crate::{emu::EmulatorModules, EmulatorHooks, Qemu};
use crate::{modules::utils::filters::{AddressFilter, PageFilter}};

#[cfg(feature = "usermode")]
pub mod usermode;
#[cfg(feature = "usermode")]
pub use usermode::*;

#[cfg(feature = "systemmode")]
pub mod systemmode;
#[cfg(feature = "systemmode")]
#[expect(unused_imports)]
pub use systemmode::*;

pub mod edges;
pub use edges::{
    EdgeCoverageModule, EdgeCoverageModuleBuilder, StdEdgeCoverageChildModule,
    StdEdgeCoverageChildModuleBuilder, StdEdgeCoverageClassicModule,
    StdEdgeCoverageClassicModuleBuilder, StdEdgeCoverageFullModule,
    StdEdgeCoverageFullModuleBuilder, StdEdgeCoverageModule, StdEdgeCoverageModuleBuilder,
};

#[cfg(not(cpu_target = "hexagon"))]
pub mod calls;
#[cfg(not(cpu_target = "hexagon"))]
pub use calls::CallTracerModule;

#[cfg(not(any(cpu_target = "mips", cpu_target = "hexagon")))]
pub mod cmplog;
#[cfg(not(any(cpu_target = "mips", cpu_target = "hexagon")))]
pub use cmplog::CmpLogModule;

#[cfg(not(cpu_target = "hexagon"))]
pub mod drcov;
#[cfg(not(cpu_target = "hexagon"))]
pub use drcov::{DrCovMetadata, DrCovModule, DrCovModuleBuilder};

pub mod utils;

/// A module for `libafl_qemu`.
// TODO remove 'static when specialization will be stable
pub trait EmulatorModule<S>: 'static + Debug
where
    S: UsesInput,
{
    type ModuleAddressFilter: AddressFilter;

    #[cfg(feature = "systemmode")]
    type ModulePageFilter: PageFilter;

    const HOOKS_DO_SIDE_EFFECTS: bool = true;

    /// Hook run **before** QEMU is initialized.
    /// This is always run when Emulator gets initialized, in any case.
    /// Install here hooks that should be alive for the whole execution of the VM, even before QEMU gets initialized.
    ///
    /// It is also possible to edit QEMU parameters, just before QEMU gets initialized.
    /// Thus, the module can modify options for QEMU just before it gets initialized.
    fn pre_qemu_init<ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _qemu_params: &mut QemuParams,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
    }

    /// Hook run **after** QEMU is initialized.
    /// This is always run when Emulator gets initialized, in any case.
    /// Install here hooks that should be alive for the whole execution of the VM, after QEMU gets initialized.
    fn post_qemu_init<ET>(&mut self, _qemu: Qemu, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
    }

    /// Run once just before fuzzing starts.
    /// This call can be delayed to the point at which fuzzing is supposed to start.
    /// It is mostly used to avoid running hooks during VM initialization, either
    /// because it is useless or it would produce wrong results.
    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
    }

    /// Run before a new fuzzing run starts.
    /// On the first run, it is executed after [`Self::first_exec`].
    fn pre_exec<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: &mut S,
        _input: &S::Input,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
    }

    /// Run after a fuzzing run ends.
    fn post_exec<OT, ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: &mut S,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S::Input, S>,
        ET: EmulatorModuleTuple<S>,
    {
    }

    /// # Safety
    ///
    /// This is getting executed in a signal handler.
    unsafe fn on_crash(&mut self) {}

    /// # Safety
    ///
    /// This is getting executed in a signal handler.
    unsafe fn on_timeout(&mut self) {}

    fn address_filter(&self) -> &Self::ModuleAddressFilter;
    fn address_filter_mut(&mut self) -> &mut Self::ModuleAddressFilter;
    fn update_address_filter(&mut self, qemu: Qemu, filter: Self::ModuleAddressFilter) {
        *self.address_filter_mut() = filter;
        // Necessary because some hooks filter during TB generation.
        qemu.flush_jit();
    }

    #[cfg(feature = "systemmode")]
    fn page_filter(&self) -> &Self::ModulePageFilter;
    #[cfg(feature = "systemmode")]
    fn page_filter_mut(&mut self) -> &mut Self::ModulePageFilter;
    #[cfg(feature = "systemmode")]
    fn update_page_filter(&mut self, qemu: Qemu, filter: Self::ModulePageFilter) {
        *self.page_filter_mut() = filter;
        // Necessary because some hooks filter during TB generation.
        qemu.flush_jit();
    }
}

pub trait EmulatorModuleTuple<S>:
    MatchFirstType + for<'a> SplitBorrowExtractFirstType<'a> + Unpin
where
    S: UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool;

    fn pre_qemu_init_all<ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        qemu_params: &mut QemuParams,
    ) where
        ET: EmulatorModuleTuple<S>;

    fn post_qemu_init_all<ET>(&mut self, qemu: Qemu, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>;

    fn first_exec_all<ET>(
        &mut self,
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, S>,
        state: &mut S,
    ) where
        ET: EmulatorModuleTuple<S>;

    fn pre_exec_all<ET>(
        &mut self,
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, S>,
        state: &mut S,
        input: &S::Input,
    ) where
        ET: EmulatorModuleTuple<S>;

    fn post_exec_all<OT, ET>(
        &mut self,
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, S>,
        state: &mut S,
        input: &S::Input,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S::Input, S>,
        ET: EmulatorModuleTuple<S>;

    /// # Safety
    ///
    /// This is getting executed in a signal handler.
    unsafe fn on_crash_all(&mut self);

    /// # Safety
    ///
    /// This is getting executed in a signal handler.
    unsafe fn on_timeout_all(&mut self);

    fn allow_address_range_all(&mut self, address_range: Range<GuestAddr>);

    #[cfg(feature = "systemmode")]
    fn allow_page_id_all(&mut self, page_id: GuestPhysAddr);
}

impl<S> EmulatorModuleTuple<S> for ()
where
    S: UsesInput + Unpin,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = false;

    fn pre_qemu_init_all<ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _qemu_params: &mut QemuParams,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn post_qemu_init_all<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, S>,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn first_exec_all<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn pre_exec_all<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: &mut S,
        _input: &S::Input,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn post_exec_all<OT, ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: &mut S,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S::Input, S>,
        ET: EmulatorModuleTuple<S>,
    {
    }

    unsafe fn on_crash_all(&mut self) {}

    unsafe fn on_timeout_all(&mut self) {}

    fn allow_address_range_all(&mut self, _address_range: Range<GuestAddr>) {}

    #[cfg(feature = "systemmode")]
    fn allow_page_id_all(&mut self, _page_id: GuestPhysAddr) {}
}

impl<Head, Tail, S> EmulatorModuleTuple<S> for (Head, Tail)
where
    Head: EmulatorModule<S> + Unpin,
    Tail: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = Head::HOOKS_DO_SIDE_EFFECTS || Tail::HOOKS_DO_SIDE_EFFECTS;

    fn pre_qemu_init_all<ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        qemu_params: &mut QemuParams,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
        self.0.pre_qemu_init(emulator_modules, qemu_params);
        self.1.pre_qemu_init_all(emulator_modules, qemu_params);
    }

    fn post_qemu_init_all<ET>(&mut self, qemu: Qemu, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        self.0.post_qemu_init(qemu, emulator_modules);
        self.1.post_qemu_init_all(qemu, emulator_modules);
    }

    fn first_exec_all<ET>(
        &mut self,
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, S>,
        state: &mut S,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
        self.0.first_exec(qemu, emulator_modules, state);
        self.1.first_exec_all(qemu, emulator_modules, state);
    }

    fn pre_exec_all<ET>(
        &mut self,
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, S>,
        state: &mut S,
        input: &S::Input,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
        self.0.pre_exec(qemu, emulator_modules, state, input);
        self.1.pre_exec_all(qemu, emulator_modules, state, input);
    }

    fn post_exec_all<OT, ET>(
        &mut self,
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, S>,
        state: &mut S,
        input: &S::Input,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S::Input, S>,
        ET: EmulatorModuleTuple<S>,
    {
        self.0
            .post_exec(qemu, emulator_modules, state, input, observers, exit_kind);
        self.1
            .post_exec_all(qemu, emulator_modules, state, input, observers, exit_kind);
    }

    unsafe fn on_crash_all(&mut self) {
        self.0.on_crash();
        self.1.on_crash_all();
    }

    unsafe fn on_timeout_all(&mut self) {
        self.0.on_timeout();
        self.1.on_timeout_all();
    }

    fn allow_address_range_all(&mut self, address_range: Range<GuestAddr>) {
        self.0.address_filter_mut().register(address_range.clone());
        self.1.allow_address_range_all(address_range);
    }

    #[cfg(feature = "systemmode")]
    fn allow_page_id_all(&mut self, page_id: GuestPhysAddr) {
        self.0.page_filter_mut().register(page_id);
        self.1.allow_page_id_all(page_id);
    }
}
