use core::fmt::Debug;

use libafl::{executors::ExitKind, observers::ObserversTuple};
use libafl_bolts::tuples::{MatchFirstType, SplitBorrowExtractFirstType};

use crate::{
    Qemu, QemuParams,
    emu::EmulatorModules,
    modules::utils::filters::{AddressFilter, PageFilter},
};

#[cfg(feature = "usermode")]
pub mod usermode;
#[cfg(feature = "usermode")]
#[cfg_attr(feature = "hexagon", allow(unused_imports))]
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

pub mod logger;
pub use logger::LoggerModule;

pub mod utils;

/// [`EmulatorModule`] is a trait designed to define modules that interact with the QEMU emulator
/// during fuzzing. [`EmulatorModule`] provides a set of interfaces (hooks) that can be invoked at various stages
/// of the fuzzer's execution.
///
/// The typical sequence of these hooks execution during a fuzzing session is as follows:
/// ```rust,ignore
/// pre_qemu_init()
/// // Qemu initialization (in the Emulator)
/// post_qemu_init()
/// // Harness initialization
/// first_exec()
///
/// // The following loop is executed for every fuzzing iteration
/// pre_exec()
/// // Harness execution
/// post_exec()
/// ```
///
/// It is important to note that all registered [`EmulatorModule`] instances will have their interfaces (hooks)
/// invoked. The order of invocation depends on the order in which the modules were registered.
///
/// Users typically add hooks, monitoring, or other instrumentation to the **fuzzing target** in [`EmulatorModule`]
/// For example:
/// ```rust,ignore
/// fn post_qemu_init<ET>(&mut self, _qemu: Qemu, _emulator_modules: &mut EmulatorModules<ET, I, S>)
/// where
///     ET: EmulatorModuleTuple<I, S>,
/// {
///     // Add a hook before the execution of a syscall in the fuzzing target
///     _emulator_modules.pre_syscalls(Hook::Function(your_syscall_hooks::<ET, I, S>))
///     // ...
/// }
/// ```
/// For more details on adding hooks to the **fuzzing target**, including function signatures,
/// return values, please refer to the [`EmulatorModules`].
// TODO remove 'static when specialization will be stable
pub trait EmulatorModule<I, S>: 'static + Debug {
    const HOOKS_DO_SIDE_EFFECTS: bool = true;

    /// Hook run **before** QEMU is initialized.
    /// This is always run when Emulator gets initialized, in any case.
    /// Install here hooks that should be alive for the whole execution of the VM, even before QEMU gets initialized.
    ///
    /// It is also possible to edit QEMU parameters, just before QEMU gets initialized.
    /// Thus, the module can modify options for QEMU just before it gets initialized.
    fn pre_qemu_init<ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _qemu_params: &mut QemuParams,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
    }

    /// Hook run **after** QEMU is initialized.
    /// This is always run when Emulator gets initialized, in any case.
    /// Install here hooks that should be alive for the whole execution of the VM, after QEMU gets initialized.
    fn post_qemu_init<ET>(&mut self, _qemu: Qemu, _emulator_modules: &mut EmulatorModules<ET, I, S>)
    where
        ET: EmulatorModuleTuple<I, S>,
    {
    }

    /// Run once just before fuzzing starts.
    /// This call can be delayed to the point at which fuzzing is supposed to start.
    /// It is mostly used to avoid running hooks during VM initialization, either
    /// because it is useless or it would produce wrong results.
    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
    }

    /// Run before a new fuzzing run starts.
    /// On the first run, it is executed after [`Self::first_exec`].
    fn pre_exec<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
    }

    /// Run after a fuzzing run ends.
    fn post_exec<OT, ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<I, S>,
        ET: EmulatorModuleTuple<I, S>,
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
}

pub trait EmulatorModuleTuple<I, S>:
    MatchFirstType + for<'a> SplitBorrowExtractFirstType<'a> + Unpin
{
    const HOOKS_DO_SIDE_EFFECTS: bool;

    fn pre_qemu_init_all<ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        qemu_params: &mut QemuParams,
    ) where
        ET: EmulatorModuleTuple<I, S>;

    fn post_qemu_init_all<ET>(
        &mut self,
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
    ) where
        ET: EmulatorModuleTuple<I, S>;

    fn first_exec_all<ET>(
        &mut self,
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>;

    fn pre_exec_all<ET>(
        &mut self,
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        state: &mut S,
        input: &I,
    ) where
        ET: EmulatorModuleTuple<I, S>;

    fn post_exec_all<OT, ET>(
        &mut self,
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        state: &mut S,
        input: &I,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<I, S>,
        ET: EmulatorModuleTuple<I, S>;

    /// # Safety
    ///
    /// This is getting executed in a signal handler.
    unsafe fn on_crash_all(&mut self);

    /// # Safety
    ///
    /// This is getting executed in a signal handler.
    unsafe fn on_timeout_all(&mut self);
}

impl<I, S> EmulatorModuleTuple<I, S> for ()
where
    S: Unpin,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = false;

    fn pre_qemu_init_all<ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _qemu_params: &mut QemuParams,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
    }

    fn post_qemu_init_all<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
    }

    fn first_exec_all<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
    }

    fn pre_exec_all<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
    }

    fn post_exec_all<OT, ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<I, S>,
        ET: EmulatorModuleTuple<I, S>,
    {
    }

    unsafe fn on_crash_all(&mut self) {}

    unsafe fn on_timeout_all(&mut self) {}
}

impl<Head, Tail, I, S> EmulatorModuleTuple<I, S> for (Head, Tail)
where
    Head: EmulatorModule<I, S> + Unpin,
    Tail: EmulatorModuleTuple<I, S>,
    S: Unpin,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = Head::HOOKS_DO_SIDE_EFFECTS || Tail::HOOKS_DO_SIDE_EFFECTS;

    fn pre_qemu_init_all<ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        qemu_params: &mut QemuParams,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        self.0.pre_qemu_init(emulator_modules, qemu_params);
        self.1.pre_qemu_init_all(emulator_modules, qemu_params);
    }

    fn post_qemu_init_all<ET>(
        &mut self,
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        self.0.post_qemu_init(qemu, emulator_modules);
        self.1.post_qemu_init_all(qemu, emulator_modules);
    }

    fn first_exec_all<ET>(
        &mut self,
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        self.0.first_exec(qemu, emulator_modules, state);
        self.1.first_exec_all(qemu, emulator_modules, state);
    }

    fn pre_exec_all<ET>(
        &mut self,
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        state: &mut S,
        input: &I,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        self.0.pre_exec(qemu, emulator_modules, state, input);
        self.1.pre_exec_all(qemu, emulator_modules, state, input);
    }

    fn post_exec_all<OT, ET>(
        &mut self,
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        state: &mut S,
        input: &I,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<I, S>,
        ET: EmulatorModuleTuple<I, S>,
    {
        self.0
            .post_exec(qemu, emulator_modules, state, input, observers, exit_kind);
        self.1
            .post_exec_all(qemu, emulator_modules, state, input, observers, exit_kind);
    }

    unsafe fn on_crash_all(&mut self) {
        unsafe {
            self.0.on_crash();
            self.1.on_crash_all();
        }
    }

    unsafe fn on_timeout_all(&mut self) {
        unsafe {
            self.0.on_timeout();
            self.1.on_timeout_all();
        }
    }
}
