use std::{
    fmt::Debug,
    ops::{Range, RangeInclusive},
};

use libafl::{HasMetadata, observers::ObserversTuple};
pub use libafl_intelpt::SectionInfo;
use libafl_intelpt::{Image, IntelPT, IntelPTBuilder};
use libafl_qemu_sys::{CPUArchStatePtr, GuestAddr};
use num_traits::SaturatingAdd;
use typed_builder::TypedBuilder;

use crate::{
    EmulatorModules, NewThreadHook, Qemu, QemuParams,
    modules::{AddressFilter, EmulatorModule, EmulatorModuleTuple, ExitKind},
};

#[derive(Debug, TypedBuilder)]
pub struct IntelPTModule<T = u8> {
    #[builder(setter(skip), default)]
    pt: Option<IntelPT>,
    #[builder(default = IntelPTModule::default_pt_builder())]
    intel_pt_builder: IntelPTBuilder,
    #[builder(setter(transform = |sections: &[SectionInfo]| {
        let mut i = Image::new(None).unwrap();
        i.add_files_cached(sections, None).unwrap();
        i
    }))]
    image: Image,
    map_ptr: *mut T,
    map_len: usize,
}

impl IntelPTModule {
    pub fn default_pt_builder() -> IntelPTBuilder {
        IntelPT::builder().exclude_kernel(false)
    }
}

impl<I, S, T> EmulatorModule<I, S> for IntelPTModule<T>
where
    I: Unpin,
    S: Unpin + HasMetadata,
    T: SaturatingAdd + From<u8> + Debug + 'static,
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
        let pt = self.pt.as_mut().expect("Intel PT module not initialized.");
        pt.enable_tracing().unwrap();
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
            .decode_traces_into_map(&mut self.image, self.map_ptr, self.map_len)
            .inspect_err(|e| log::warn!("Intel PT trace decode failed: {e}"));

        #[cfg(feature = "intel_pt_export_raw")]
        {
            let _ = pt
                .dump_last_trace_to_file()
                .inspect_err(|e| log::warn!("Intel PT trace save to file failed: {e}"));
        }
    }
}

impl<T> AddressFilter for IntelPTModule<T>
where
    T: Debug + 'static,
{
    fn register(&mut self, address_range: &Range<GuestAddr>) {
        let pt = self.pt.as_mut().unwrap();
        let mut filters = pt.ip_filters();
        let range_inclusive =
            RangeInclusive::new(address_range.start as usize, address_range.end as usize - 1);
        filters.push(range_inclusive);
        pt.set_ip_filters(&filters).unwrap()
    }

    fn allowed(&self, address: &GuestAddr) -> bool {
        let pt = self.pt.as_ref().unwrap();
        for f in pt.ip_filters() {
            if f.contains(&(*address as usize)) {
                return true;
            }
        }
        false
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

    if intel_pt_module.pt.is_some() {
        panic!("Intel PT module already initialized, only single core VMs are supported ATM.");
    }

    let pt = intel_pt_module
        .intel_pt_builder
        .clone()
        .pid(Some(tid as i32))
        .build()
        .unwrap();

    intel_pt_module.pt = Some(pt);

    true
}
