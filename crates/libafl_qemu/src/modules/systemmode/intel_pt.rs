use std::fmt::Debug;

use libafl::{HasMetadata, observers::ObserversTuple};
pub use libafl_intelpt::PtImage;
use libafl_intelpt::{CoverageEntry, IntelPT, IntelPTBuilder};
use libafl_qemu_sys::CPUArchStatePtr;
use typed_builder::TypedBuilder;

use crate::{
    EmulatorModules, NewThreadHook, Qemu, QemuParams,
    modules::{EmulatorModule, EmulatorModuleTuple, ExitKind},
};

#[derive(Debug, TypedBuilder)]
pub struct IntelPTModule<T = u8> {
    #[builder(setter(skip), default)]
    pt: Option<IntelPT>,
    #[builder(default = IntelPTModule::default_pt_builder())]
    intel_pt_builder: IntelPTBuilder,
    map_ptr: *mut T,
    map_len: usize,
}

impl IntelPTModule {
    #[must_use]
    pub fn default_pt_builder() -> IntelPTBuilder {
        IntelPT::builder().exclude_kernel(false).exclude_hv(true)
    }
}

impl<T> IntelPTModule<T> {
    pub fn enable_tracing(&mut self) {
        let pt = self.pt.as_mut().expect("Intel PT module not initialized.");
        pt.enable_tracing().unwrap();
    }
}

impl<I, S, T> EmulatorModule<I, S> for IntelPTModule<T>
where
    I: Unpin,
    S: Unpin + HasMetadata,
    T: CoverageEntry + 'static,
{
    fn pre_qemu_init<ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _qemu_params: &mut QemuParams,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        emulator_modules
            .thread_creation(NewThreadHook::Function(intel_pt_new_thread::<ET, I, S, T>))
            .unwrap();
        log::trace!("Intel PT thread creation hook added.");
        // fixme: consider implementing a clean emulator_modules.thread_teradown
    }

    fn pre_exec<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        assert!(self.pt.is_some(), "Intel PT module not initialized.");
    }

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
        let pt = self.pt.as_mut().expect("Intel PT module not initialized.");
        pt.disable_tracing().unwrap();

        let _ = pt
            .decode_traces_into_map(self.map_ptr, self.map_len)
            .inspect_err(|e| log::warn!("Intel PT trace decode failed: {e}"));

        #[cfg(feature = "intel_pt_export_raw")]
        {
            let _ = pt
                .dump_last_trace_to_file()
                .inspect_err(|e| log::warn!("Intel PT trace save to file failed: {e}"));
        }
    }
}

pub fn intel_pt_new_thread<ET, I, S, T>(
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    _env: CPUArchStatePtr,
    tid: u32,
) -> bool
where
    I: Unpin,
    S: HasMetadata + Unpin,
    ET: EmulatorModuleTuple<I, S>,
    T: Debug + 'static,
{
    let intel_pt_module = emulator_modules
        .modules_mut()
        .match_first_type_mut::<IntelPTModule<T>>()
        .unwrap();

    assert!(
        intel_pt_module.pt.is_none(),
        "Intel PT module already initialized, only single core VMs are supported ATM."
    );

    let pt = intel_pt_module
        .intel_pt_builder
        .clone()
        .pid(Some(tid.try_into().unwrap()))
        .build()
        .unwrap();

    intel_pt_module.pt = Some(pt);

    log::trace!("Intel PT attached to thread {tid}");

    true
}
