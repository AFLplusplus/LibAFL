use std::{cell::UnsafeCell, cmp::max, ptr, ptr::addr_of};

use hashbrown::{hash_map::Entry, HashMap};
use libafl::{inputs::UsesInput, HasMetadata};
use libafl_qemu_sys::GuestAddr;
use libafl_targets::EDGES_MAP;
use serde::{Deserialize, Serialize};

use crate::{
    modules::{
        hash_me, AddressFilter, EdgeCoverageModule, EdgeCoverageVariant, EmulatorModuleTuple,
        PageFilter,
    },
    EmulatorModules,
};

#[no_mangle]
pub(crate) static mut LIBAFL_QEMU_EDGES_MAP_PTR: *mut u8 = ptr::null_mut();

#[no_mangle]
pub(crate) static mut LIBAFL_QEMU_EDGES_MAP_SIZE_PTR: *mut usize = ptr::null_mut();

#[no_mangle]
pub(crate) static mut LIBAFL_QEMU_EDGES_MAP_ALLOCATED_SIZE: usize = 0;

#[no_mangle]
pub(crate) static mut LIBAFL_QEMU_EDGES_MAP_MASK_MAX: usize = 0;

#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct QemuEdgesMapMetadata {
    pub map: HashMap<(GuestAddr, GuestAddr), u64>,
    pub current_id: u64,
}

libafl_bolts::impl_serdeany!(QemuEdgesMapMetadata);

impl QemuEdgesMapMetadata {
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            current_id: 0,
        }
    }
}

thread_local!(static PREV_LOC : UnsafeCell<u64> = const { UnsafeCell::new(0) });

pub fn gen_unique_edge_ids<AF, ET, PF, S, V>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    state: Option<&mut S>,
    src: GuestAddr,
    dest: GuestAddr,
) -> Option<u64>
where
    AF: AddressFilter,
    ET: EmulatorModuleTuple<S>,
    PF: PageFilter,
    S: Unpin + UsesInput + HasMetadata,
    V: EdgeCoverageVariant<AF, PF>,
{
    if let Some(module) = emulator_modules.get::<EdgeCoverageModule<AF, PF, V>>() {
        unsafe {
            assert!(LIBAFL_QEMU_EDGES_MAP_MASK_MAX > 0);
            assert_ne!(*addr_of!(LIBAFL_QEMU_EDGES_MAP_SIZE_PTR), ptr::null_mut());
        }

        #[cfg(emulation_mode = "usermode")]
        {
            if !module.must_instrument(src) && !module.must_instrument(dest) {
                return None;
            }
        }

        #[cfg(emulation_mode = "systemmode")]
        {
            let paging_id = emulator_modules
                .qemu()
                .current_cpu()
                .and_then(|cpu| cpu.current_paging_id());

            if !module.must_instrument(src, paging_id) && !module.must_instrument(dest, paging_id) {
                return None;
            }
        }
    }

    let state = state.expect("The gen_unique_edge_ids hook works only for in-process fuzzing");
    let meta = state.metadata_or_insert_with(QemuEdgesMapMetadata::new);

    match meta.map.entry((src, dest)) {
        Entry::Occupied(e) => {
            let id = *e.get();
            unsafe {
                let nxt = (id as usize + 1) & LIBAFL_QEMU_EDGES_MAP_MASK_MAX;
                *LIBAFL_QEMU_EDGES_MAP_SIZE_PTR = max(*LIBAFL_QEMU_EDGES_MAP_SIZE_PTR, nxt);
            }
            Some(id)
        }
        Entry::Vacant(e) => {
            let id = meta.current_id;
            e.insert(id);
            unsafe {
                meta.current_id = (id + 1) & (LIBAFL_QEMU_EDGES_MAP_MASK_MAX as u64);
                *LIBAFL_QEMU_EDGES_MAP_SIZE_PTR = meta.current_id as usize;
            }
            // GuestAddress is u32 for 32 bit guests
            #[allow(clippy::unnecessary_cast)]
            Some(id as u64)
        }
    }
}

// # Safety
// Calling this concurrently for the same id is racey and may lose updates.
pub unsafe extern "C" fn trace_edge_hitcount(_: *const (), id: u64) {
    unsafe {
        EDGES_MAP[id as usize] = EDGES_MAP[id as usize].wrapping_add(1);
    }
}

pub extern "C" fn trace_edge_single(_: *const (), id: u64) {
    // # Safety
    // Worst case we set the byte to 1 multiple times..
    unsafe {
        EDGES_MAP[id as usize] = 1;
    }
}

#[allow(clippy::unnecessary_cast)]
pub fn gen_hashed_edge_ids<AF, ET, PF, S, V>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    src: GuestAddr,
    dest: GuestAddr,
) -> Option<u64>
where
    AF: AddressFilter,
    ET: EmulatorModuleTuple<S>,
    PF: PageFilter,
    S: Unpin + UsesInput + HasMetadata,
    V: EdgeCoverageVariant<AF, PF>,
{
    if let Some(module) = emulator_modules.get::<EdgeCoverageModule<AF, PF, V>>() {
        #[cfg(emulation_mode = "usermode")]
        if !module.must_instrument(src) && !module.must_instrument(dest) {
            return None;
        }

        #[cfg(emulation_mode = "systemmode")]
        {
            let paging_id = emulator_modules
                .qemu()
                .current_cpu()
                .and_then(|cpu| cpu.current_paging_id());

            if !module.must_instrument(src, paging_id) && !module.must_instrument(dest, paging_id) {
                return None;
            }
        }

        let id = hash_me(src as u64) ^ hash_me(dest as u64);

        unsafe {
            let nxt = (id as usize + 1) & LIBAFL_QEMU_EDGES_MAP_MASK_MAX;
            *LIBAFL_QEMU_EDGES_MAP_SIZE_PTR = nxt;
        }

        // GuestAddress is u32 for 32 bit guests
        #[allow(clippy::unnecessary_cast)]
        Some(id)
    } else {
        None
    }
}

/// # Safety
/// Increases id at `EDGES_MAP_PTR` - potentially racey if called concurrently.
pub unsafe extern "C" fn trace_edge_hitcount_ptr(_: *const (), id: u64) {
    unsafe {
        let ptr = LIBAFL_QEMU_EDGES_MAP_PTR.add(id as usize);
        *ptr = (*ptr).wrapping_add(1);
    }
}

/// # Safety
/// Fine.
/// Worst case we set the byte to 1 multiple times.
pub unsafe extern "C" fn trace_edge_single_ptr(_: *const (), id: u64) {
    unsafe {
        let ptr = LIBAFL_QEMU_EDGES_MAP_PTR.add(id as usize);
        *ptr = 1;
    }
}

#[allow(clippy::unnecessary_cast)]
pub fn gen_hashed_block_ids<AF, ET, PF, S, V>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
) -> Option<u64>
where
    AF: AddressFilter,
    ET: EmulatorModuleTuple<S>,
    PF: PageFilter,
    S: Unpin + UsesInput + HasMetadata,
    V: EdgeCoverageVariant<AF, PF>,
{
    // first check if we should filter
    if let Some(module) = emulator_modules.get::<EdgeCoverageModule<AF, PF, V>>() {
        #[cfg(emulation_mode = "usermode")]
        {
            if !module.must_instrument(pc) {
                return None;
            }
        }
        #[cfg(emulation_mode = "systemmode")]
        {
            let page_id = emulator_modules
                .qemu()
                .current_cpu()
                .and_then(|cpu| cpu.current_paging_id());

            if !module.must_instrument(pc, page_id) {
                return None;
            }
        }
    }

    let id = hash_me(pc as u64);

    unsafe {
        let nxt = (id as usize + 1) & LIBAFL_QEMU_EDGES_MAP_MASK_MAX;
        *LIBAFL_QEMU_EDGES_MAP_SIZE_PTR = nxt;
    }

    // GuestAddress is u32 for 32 bit guests
    #[allow(clippy::unnecessary_cast)]
    Some(id)
}

/// # Safety
/// Dereferences the global `PREV_LOC` variable. May not be called concurrently.
pub unsafe extern "C" fn trace_block_transition_hitcount(_: *const (), id: u64) {
    unsafe {
        PREV_LOC.with(|prev_loc| {
            let x = ((*prev_loc.get() ^ id) as usize) & LIBAFL_QEMU_EDGES_MAP_MASK_MAX;
            let entry = LIBAFL_QEMU_EDGES_MAP_PTR.add(x);
            *entry = (*entry).wrapping_add(1);
            *prev_loc.get() = id.overflowing_shr(1).0;
        });
    }
}

/// # Safety
/// Dereferences the global `PREV_LOC` variable. May not be called concurrently.
pub unsafe extern "C" fn trace_block_transition_single(_: *const (), id: u64) {
    unsafe {
        PREV_LOC.with(|prev_loc| {
            let x = ((*prev_loc.get() ^ id) as usize) & LIBAFL_QEMU_EDGES_MAP_MASK_MAX;
            let entry = LIBAFL_QEMU_EDGES_MAP_PTR.add(x);
            *entry = 1;
            *prev_loc.get() = id.overflowing_shr(1).0;
        });
    }
}
