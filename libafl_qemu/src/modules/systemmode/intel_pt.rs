use std::{
    fmt::Debug,
    ops::{Range, RangeInclusive},
    ptr::slice_from_raw_parts_mut,
};

use libafl::{inputs::UsesInput, observers::ObserversTuple, HasMetadata};
use libafl_intelpt::IntelPT;
use libafl_qemu_sys::{CPUArchStatePtr, GuestAddr};
use num_traits::SaturatingAdd;

use crate::{
    modules::{AddressFilter, EmulatorModule, EmulatorModuleTuple, ExitKind, NopPageFilter},
    EmulatorModules, NewThreadHook,
};

#[derive(Debug)]
pub struct IntelPTModule<T = u8>
where
    T: Debug,
{
    pt: Option<IntelPT>,
    map_ptr: *mut T,
    map_len: usize,
}

pub fn intel_pt_new_thread<ET, S, T>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    _env: CPUArchStatePtr,
    tid: u32,
) -> bool
where
    S: HasMetadata + Unpin + UsesInput,
    ET: EmulatorModuleTuple<S>,
    T: Debug + 'static,
{
    let intel_pt_module = emulator_modules
        .modules_mut()
        .match_first_type_mut::<IntelPTModule<T>>()
        .unwrap();

    if intel_pt_module.pt.is_some() {
        panic!("Intel PT module already initialized, only single core VMs are supported ATM.");
    }

    intel_pt_module.pt = Some(IntelPT::builder().pid(Some(tid as i32)).build().unwrap());
    intel_pt_module
        .pt
        .as_mut()
        .unwrap()
        .enable_tracing()
        .unwrap();

    println!("IntelPT initialized!");
    // What does this bool mean? ignore for the moment
    true
}

impl<S, T> EmulatorModule<S> for IntelPTModule<T>
where
    S: Unpin + UsesInput + HasMetadata,
    T: SaturatingAdd + From<u8> + Debug + 'static,
{
    type ModuleAddressFilter = Self;
    type ModulePageFilter = NopPageFilter;

    fn first_exec<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>, _state: &mut S)
    where
        ET: EmulatorModuleTuple<S>,
    {
        emulator_modules.thread_creation(NewThreadHook::Function(intel_pt_new_thread::<ET, S, T>));
        // TODO emulator_modules.thread_teradown
    }

    fn pre_exec<ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: &mut S,
        _input: &<S as UsesInput>::Input,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
        let pt = self.pt.as_mut().expect("Intel PT module not initialized.");
        pt.enable_tracing().unwrap();
    }

    fn post_exec<OT, ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        _state: &mut S,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S::Input, S>,
        ET: EmulatorModuleTuple<S>,
    {
        let pt = self.pt.as_mut().expect("Intel PT module not initialized.");
        pt.disable_tracing().unwrap();

        // we need the memory map to decode the traces here take it in prexec. use QemuMemoryChunk
        // TODO handle self modifying code

        let qemu = emulator_modules.qemu();
        pt.decode_with_callback(
            |addr, out_buff| qemu.read_mem(out_buff, addr.into()).unwrap(),
            unsafe { &mut *slice_from_raw_parts_mut(self.map_ptr, self.map_len) },
        )
        .unwrap();

        // let trace_path = "trace.out";
        // let mut file = OpenOptions::new()
        //     .append(true)
        //     .create(true)
        //     .open(trace_path)
        //     .expect("Failed to open trace output file");
        //
        // file.write_all(&buff).unwrap();
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
