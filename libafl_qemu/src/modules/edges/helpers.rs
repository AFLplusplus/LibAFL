use std::ptr;

/// Generators, responsible for generating block/edge ids
pub use generators::{gen_hashed_block_ids, gen_hashed_edge_ids, gen_unique_edge_ids};
use hashbrown::HashMap;
use libafl_qemu_sys::GuestAddr;
use serde::{Deserialize, Serialize};
/// Tracers, responsible for propagating an ID in a map.
pub use tracers::{
    trace_block_transition_hitcount, trace_block_transition_single, trace_edge_hitcount,
    trace_edge_hitcount_ptr, trace_edge_single, trace_edge_single_ptr,
};

// Constants used for variable-length maps

#[unsafe(no_mangle)]
pub(super) static mut LIBAFL_QEMU_EDGES_MAP_PTR: *mut u8 = ptr::null_mut();

#[unsafe(no_mangle)]
pub(super) static mut LIBAFL_QEMU_EDGES_MAP_SIZE_PTR: *mut usize = ptr::null_mut();

#[unsafe(no_mangle)]
pub(super) static mut LIBAFL_QEMU_EDGES_MAP_ALLOCATED_SIZE: usize = 0;

#[unsafe(no_mangle)]
pub(super) static mut LIBAFL_QEMU_EDGES_MAP_MASK_MAX: usize = 0;

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

mod generators {
    use std::{cmp::max, ptr};

    use hashbrown::hash_map::Entry;
    use libafl::HasMetadata;
    use libafl_bolts::hash_64_fast;
    use libafl_qemu_sys::GuestAddr;

    use super::{
        super::EdgeCoverageVariant, LIBAFL_QEMU_EDGES_MAP_MASK_MAX, LIBAFL_QEMU_EDGES_MAP_SIZE_PTR,
        QemuEdgesMapMetadata,
    };
    use crate::{
        EmulatorModules, Qemu,
        modules::{AddressFilter, EdgeCoverageModule, EmulatorModuleTuple, PageFilter},
    };

    fn get_mask<const IS_CONST_MAP: bool, const MAP_SIZE: usize>() -> usize {
        if IS_CONST_MAP {
            const {
                assert!(
                    !IS_CONST_MAP || MAP_SIZE > 0,
                    "The size of a const map should be bigger than 0."
                );
                MAP_SIZE.overflowing_sub(1).0
            }
        } else {
            unsafe { LIBAFL_QEMU_EDGES_MAP_MASK_MAX }
        }
    }

    #[allow(unused_variables)]
    pub fn gen_unique_edge_ids<
        AF,
        ET,
        PF,
        I,
        S,
        V,
        const IS_CONST_MAP: bool,
        const MAP_SIZE: usize,
    >(
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        state: Option<&mut S>,
        src: GuestAddr,
        dest: GuestAddr,
    ) -> Option<u64>
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<I, S>,
        PF: PageFilter,
        I: Unpin,
        S: HasMetadata + Unpin,
        V: EdgeCoverageVariant<AF, PF, IS_CONST_MAP, MAP_SIZE>,
    {
        if let Some(module) =
            emulator_modules.get::<EdgeCoverageModule<AF, PF, V, IS_CONST_MAP, MAP_SIZE>>()
        {
            unsafe {
                assert!(LIBAFL_QEMU_EDGES_MAP_MASK_MAX > 0);
                let edges_map_size_ptr = &raw const LIBAFL_QEMU_EDGES_MAP_SIZE_PTR;
                assert_ne!(*edges_map_size_ptr, ptr::null_mut());
            }

            #[cfg(feature = "usermode")]
            {
                if !module.must_instrument(src) && !module.must_instrument(dest) {
                    return None;
                }
            }

            #[cfg(feature = "systemmode")]
            {
                let paging_id = qemu.current_cpu().and_then(|cpu| cpu.current_paging_id());

                if !module.must_instrument(src, paging_id)
                    && !module.must_instrument(dest, paging_id)
                {
                    return None;
                }
            }
        }

        let mask: usize = get_mask::<IS_CONST_MAP, MAP_SIZE>();

        let state = state.expect("The gen_unique_edge_ids hook works only for in-process fuzzing. Is the Executor initialized?");
        let meta = state.metadata_or_insert_with(QemuEdgesMapMetadata::new);

        match meta.map.entry((src, dest)) {
            Entry::Occupied(e) => {
                let id = *e.get();
                unsafe {
                    let nxt = (id as usize + 1) & mask;

                    if !IS_CONST_MAP {
                        *LIBAFL_QEMU_EDGES_MAP_SIZE_PTR = max(*LIBAFL_QEMU_EDGES_MAP_SIZE_PTR, nxt);
                    }
                }
                Some(id)
            }
            Entry::Vacant(e) => {
                let id = meta.current_id;
                e.insert(id);
                unsafe {
                    meta.current_id = (id + 1) & (mask as u64);

                    if !IS_CONST_MAP {
                        *LIBAFL_QEMU_EDGES_MAP_SIZE_PTR = meta.current_id as usize;
                    }
                }
                // GuestAddress is u32 for 32 bit guests
                #[expect(clippy::unnecessary_cast)]
                Some(id as u64)
            }
        }
    }

    #[allow(unused_variables)]
    #[allow(clippy::needless_pass_by_value)] // no longer a problem with nightly
    pub fn gen_hashed_edge_ids<
        AF,
        ET,
        PF,
        I,
        S,
        V,
        const IS_CONST_MAP: bool,
        const MAP_SIZE: usize,
    >(
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: Option<&mut S>,
        src: GuestAddr,
        dest: GuestAddr,
    ) -> Option<u64>
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<I, S>,
        PF: PageFilter,
        I: Unpin,
        S: HasMetadata + Unpin,
        V: EdgeCoverageVariant<AF, PF, IS_CONST_MAP, MAP_SIZE>,
    {
        if let Some(module) =
            emulator_modules.get::<EdgeCoverageModule<AF, PF, V, IS_CONST_MAP, MAP_SIZE>>()
        {
            #[cfg(feature = "usermode")]
            if !module.must_instrument(src) && !module.must_instrument(dest) {
                return None;
            }

            #[cfg(feature = "systemmode")]
            {
                let paging_id = qemu.current_cpu().and_then(|cpu| cpu.current_paging_id());

                if !module.must_instrument(src, paging_id)
                    && !module.must_instrument(dest, paging_id)
                {
                    return None;
                }
            }

            let mask = get_mask::<IS_CONST_MAP, MAP_SIZE>() as u64;

            #[expect(clippy::unnecessary_cast)]
            let id = (hash_64_fast(src as u64) ^ hash_64_fast(dest as u64)) & mask;

            if !IS_CONST_MAP {
                unsafe {
                    *LIBAFL_QEMU_EDGES_MAP_SIZE_PTR =
                        max(*LIBAFL_QEMU_EDGES_MAP_SIZE_PTR, id as usize);
                }
            }

            Some(id)
        } else {
            None
        }
    }

    #[expect(clippy::unnecessary_cast)]
    #[allow(unused_variables)]
    #[allow(clippy::needless_pass_by_value)] // no longer a problem with nightly
    pub fn gen_hashed_block_ids<
        AF,
        ET,
        PF,
        I,
        S,
        V,
        const IS_CONST_MAP: bool,
        const MAP_SIZE: usize,
    >(
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: Option<&mut S>,
        pc: GuestAddr,
    ) -> Option<u64>
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<I, S>,
        PF: PageFilter,
        I: Unpin,
        S: HasMetadata + Unpin,
        V: EdgeCoverageVariant<AF, PF, IS_CONST_MAP, MAP_SIZE>,
    {
        // first check if we should filter
        if let Some(module) =
            emulator_modules.get::<EdgeCoverageModule<AF, PF, V, IS_CONST_MAP, MAP_SIZE>>()
        {
            #[cfg(feature = "usermode")]
            {
                if !module.must_instrument(pc) {
                    return None;
                }
            }
            #[cfg(feature = "systemmode")]
            {
                let page_id = qemu.current_cpu().and_then(|cpu| cpu.current_paging_id());

                if !module.must_instrument(pc, page_id) {
                    return None;
                }
            }
        }

        let mask = get_mask::<IS_CONST_MAP, MAP_SIZE>() as u64;

        let id = hash_64_fast(pc as u64) & mask;

        if !IS_CONST_MAP {
            unsafe {
                *LIBAFL_QEMU_EDGES_MAP_SIZE_PTR = max(*LIBAFL_QEMU_EDGES_MAP_SIZE_PTR, id as usize);
            }
        }

        Some(id)
    }
}

mod tracers {
    use std::cell::UnsafeCell;

    use libafl_targets::EDGES_MAP;

    use super::{LIBAFL_QEMU_EDGES_MAP_MASK_MAX, LIBAFL_QEMU_EDGES_MAP_PTR};

    thread_local!(static PREV_LOC : UnsafeCell<u64> = const { UnsafeCell::new(0) });

    /// # Safety
    ///
    /// - @id should be the one generated by a gen_* function from this module.
    /// - Calling this concurrently for the same id is racey and may lose updates.
    pub unsafe extern "C" fn trace_edge_hitcount(_: *const (), id: u64) {
        unsafe {
            EDGES_MAP[id as usize] = EDGES_MAP[id as usize].wrapping_add(1);
        }
    }

    /// # Safety
    ///
    /// - @id should be the one generated by a gen_* function from this module.
    pub unsafe extern "C" fn trace_edge_single(_: *const (), id: u64) {
        // # Safety
        // Worst case we set the byte to 1 multiple times..
        unsafe {
            EDGES_MAP[id as usize] = 1;
        }
    }

    /// # Safety
    ///
    /// Increases id at `EDGES_MAP_PTR` - potentially racey if called concurrently.
    pub unsafe extern "C" fn trace_edge_hitcount_ptr(_: *const (), id: u64) {
        unsafe {
            let ptr = LIBAFL_QEMU_EDGES_MAP_PTR.add(id as usize);
            *ptr = (*ptr).wrapping_add(1);
        }
    }

    /// # Safety
    ///
    /// Fine.
    /// Worst case we set the byte to 1 multiple times.
    pub unsafe extern "C" fn trace_edge_single_ptr(_: *const (), id: u64) {
        unsafe {
            let ptr = LIBAFL_QEMU_EDGES_MAP_PTR.add(id as usize);
            *ptr = 1;
        }
    }

    /// # Safety
    ///
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
    ///
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
}
