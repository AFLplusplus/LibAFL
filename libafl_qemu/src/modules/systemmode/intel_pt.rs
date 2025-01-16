use std::{
    fmt::Debug,
    ops::{Range, RangeInclusive},
    rc::Rc,
};

use libafl::{observers::ObserversTuple, Error, HasMetadata};
use libafl_intelpt::{error_from_pt_error, Image, IntelPT, IntelPTBuilder, SectionCache};
use libafl_qemu_sys::{CPUArchStatePtr, GuestAddr};
use num_traits::SaturatingAdd;
use typed_builder::TypedBuilder;

use crate::{
    modules::{
        utils::filters::NopPageFilter, AddressFilter, EmulatorModule, EmulatorModuleTuple, ExitKind,
    },
    EmulatorModules, NewThreadHook, Qemu, QemuParams,
};

#[derive(Debug, TypedBuilder)]
pub struct IntelPTModule<T = u8> {
    #[builder(setter(skip), default)]
    pt: Option<IntelPT>,
    #[builder(default = IntelPTModule::default_pt_builder())]
    intel_pt_builder: IntelPTBuilder,
    #[builder(setter(transform = |sections: &[Section]| sections_to_image(sections).unwrap()))]
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
    type ModuleAddressFilter = Self;
    type ModulePageFilter = NopPageFilter;

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
        // TODO emulator_modules.thread_teradown
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
        // TODO handle self modifying code

        // TODO log errors or panic or smth
        // let _ = pt.decode_with_callback(
        //     |addr, out_buff| {
        //         let _ = qemu.read_mem(out_buff, addr.into());
        //     },
        //     unsafe { &mut *slice_from_raw_parts_mut(self.map_ptr, self.map_len) },
        // );

        let _ = pt.decode_traces_into_map(&mut self.image, self.map_ptr, self.map_len);

        #[cfg(feature = "intel_pt_export_raw")]
        {
            let _ = pt
                .dump_last_trace_to_file()
                .inspect_err(|e| log::warn!("Intel PT trace save to file failed: {e}"));
        }
    }

    fn address_filter(&self) -> &Self::ModuleAddressFilter {
        self
    }

    fn address_filter_mut(&mut self) -> &mut Self::ModuleAddressFilter {
        self
    }

    fn page_filter(&self) -> &Self::ModulePageFilter {
        unimplemented!()
    }

    fn page_filter_mut(&mut self) -> &mut Self::ModulePageFilter {
        unimplemented!()
    }
}

impl<T> AddressFilter for IntelPTModule<T>
where
    T: Debug + 'static,
{
    fn register(&mut self, address_range: Range<GuestAddr>) {
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

    // What does this bool mean? ignore for the moment
    true
}

// It would be nice to have this as a `TryFrom<IntoIter<Section>>`, but Rust's orphan rule doesn't
// like this (and `TryFromIter` is not a thing atm)
fn sections_to_image(sections: &[Section]) -> Result<Image, Error> {
    let mut image_cache = SectionCache::new(Some("image_cache")).map_err(error_from_pt_error)?;
    let mut image = Image::new(Some("image")).map_err(error_from_pt_error)?;

    let mut isids = Vec::with_capacity(sections.len());
    for s in sections {
        let isid = image_cache.add_file(&s.file_path, s.file_offset, s.size, s.virtual_address);
        match isid {
            Err(e) => log::warn!(
                "Error while caching {} {} - skipped",
                s.file_path,
                e.to_string()
            ),
            Ok(id) => isids.push(id),
        }
    }

    let rc_cache = Rc::new(image_cache);
    for isid in isids {
        if let Err(e) = image.add_cached(rc_cache.clone(), isid, None) {
            log::warn!("Error while adding cache to image {}", e.to_string());
        }
    }

    Ok(image)
}

/// Info of a binary's section that can be used during `Intel PT` traces decoding
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Path of the binary
    pub file_path: String,
    /// Offset of the section in the file
    pub file_offset: u64,
    /// Size of the section
    pub size: u64,
    /// Start virtual address of the section once loaded in memory
    pub virtual_address: u64,
}
