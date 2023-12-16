use std::{cell::UnsafeCell, cmp::max};

use hashbrown::{hash_map::Entry, HashMap};
use libafl::{inputs::UsesInput, state::HasMetadata};
pub use libafl_targets::{
    edges_map_mut_ptr, edges_map_mut_slice, edges_max_num, std_edges_map_observer, EDGES_MAP,
    EDGES_MAP_PTR, EDGES_MAP_PTR_NUM, EDGES_MAP_SIZE, MAX_EDGES_NUM,
};
use serde::{Deserialize, Serialize};

use crate::{
    emu::GuestAddr,
    helper::{
        hash_me, HasInstrumentationFilter, QemuHelper, QemuHelperTuple, QemuInstrumentationFilter,
    },
    hooks::{Hook, QemuHooks},
};

#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct QemuEdgesMapMetadata {
    pub map: HashMap<(GuestAddr, GuestAddr), u64>,
    pub current_id: u64,
}

impl QemuEdgesMapMetadata {
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            current_id: 0,
        }
    }
}

libafl_bolts::impl_serdeany!(QemuEdgesMapMetadata);

#[derive(Debug)]
pub struct CustomCall {
    pub guest_addr: GuestAddr,
    pub value: u8,
    //    function: Function,
}

#[derive(Debug)]
pub struct QemuEdgeCoverageHelper {
    filter: QemuInstrumentationFilter,
    use_hitcounts: bool,
    instrument_call_targets: Vec<CustomCall>,
}

impl QemuEdgeCoverageHelper {
    #[must_use]
    pub fn new(filter: QemuInstrumentationFilter) -> Self {
        Self {
            filter,
            use_hitcounts: true,
            instrument_call_targets: vec![],
        }
    }

    #[must_use]
    pub fn without_hitcounts(filter: QemuInstrumentationFilter) -> Self {
        Self {
            filter,
            use_hitcounts: false,
            instrument_call_targets: vec![],
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.filter.allowed(addr)
    }

    #[must_use]
    pub fn add_custom_call_target(&mut self, v: CustomCall) {
        self.instrument_call_targets.push(v);
    }

    /*
        pub fn get_instrument_call_targets(&self) -> Vec<CustomCall> {
            self.instrument_call_targets
        }
    */
}

impl Default for QemuEdgeCoverageHelper {
    fn default() -> Self {
        Self::new(QemuInstrumentationFilter::None)
    }
}

impl HasInstrumentationFilter for QemuEdgeCoverageHelper {
    fn filter(&self) -> &QemuInstrumentationFilter {
        &self.filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationFilter {
        &mut self.filter
    }
}

impl<S> QemuHelper<S> for QemuEdgeCoverageHelper
where
    S: UsesInput + HasMetadata,
{
    fn first_exec<QT>(&self, hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        if self.use_hitcounts {
            // hooks.edges(
            //     Hook::Function(gen_unique_edge_ids::<QT, S>),
            //     Hook::Raw(trace_edge_hitcount),
            // );
            let hook_id = hooks.edges(Hook::Function(gen_unique_edge_ids::<QT, S>), Hook::Empty);
            unsafe {
                libafl_qemu_sys::libafl_qemu_edge_hook_set_jit(
                    hook_id.0,
                    Some(libafl_qemu_sys::libafl_jit_trace_edge_hitcount),
                );
            }
        } else {
            // hooks.edges(
            //     Hook::Function(gen_unique_edge_ids::<QT, S>),
            //     Hook::Raw(trace_edge_single),
            // );
            let hook_id = hooks.edges(Hook::Function(gen_unique_edge_ids::<QT, S>), Hook::Empty);
            unsafe {
                libafl_qemu_sys::libafl_qemu_edge_hook_set_jit(
                    hook_id.0,
                    Some(libafl_qemu_sys::libafl_jit_trace_edge_single),
                );
            }
        }
        #[cfg(emulation_mode = "usermode")]
        if self.instrument_call_targets.len() > 0 {
            hooks.blocks(
                Hook::Function(QemuCustomCallHelper::gen_blocks_custom_calls::<QT, S>),
                Hook::Empty,
                Hook::Empty,
            );
        }
    }
}

pub type QemuCollidingEdgeCoverageHelper = QemuEdgeCoverageChildHelper;

#[derive(Debug)]
pub struct QemuEdgeCoverageChildHelper {
    filter: QemuInstrumentationFilter,
    use_hitcounts: bool,
    instrument_call_targets: Vec<CustomCall>,
}

impl QemuEdgeCoverageChildHelper {
    #[must_use]
    pub fn new(filter: QemuInstrumentationFilter) -> Self {
        Self {
            filter,
            use_hitcounts: true,
            instrument_call_targets: vec![],
        }
    }

    #[must_use]
    pub fn without_hitcounts(filter: QemuInstrumentationFilter) -> Self {
        Self {
            filter,
            use_hitcounts: false,
            instrument_call_targets: vec![],
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.filter.allowed(addr)
    }

    #[must_use]
    pub fn add_custom_call_target(&mut self, v: CustomCall) {
        self.instrument_call_targets.push(v);
    }

    /*
        pub fn get_instrument_call_targets(&self) -> Vec<CustomCall> {
            self.instrument_call_targets
        }
    */
}

impl Default for QemuEdgeCoverageChildHelper {
    fn default() -> Self {
        Self::new(QemuInstrumentationFilter::None)
    }
}

impl HasInstrumentationFilter for QemuEdgeCoverageChildHelper {
    fn filter(&self) -> &QemuInstrumentationFilter {
        &self.filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationFilter {
        &mut self.filter
    }
}

impl<S> QemuHelper<S> for QemuEdgeCoverageChildHelper
where
    S: UsesInput,
    S: HasMetadata,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = false;

    fn first_exec<QT>(&self, hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        if self.use_hitcounts {
            hooks.edges(
                Hook::Function(gen_hashed_edge_ids::<QT, S>),
                Hook::Raw(trace_edge_hitcount_ptr),
            );
        } else {
            hooks.edges(
                Hook::Function(gen_hashed_edge_ids::<QT, S>),
                Hook::Raw(trace_edge_single_ptr),
            );
        }
    }
}

#[derive(Debug)]
pub struct QemuEdgeCoverageClassicHelper {
    filter: QemuInstrumentationFilter,
    use_hitcounts: bool,
    instrument_call_targets: Vec<CustomCall>,
}

impl QemuEdgeCoverageClassicHelper {
    #[must_use]
    pub fn new(filter: QemuInstrumentationFilter) -> Self {
        Self {
            filter,
            use_hitcounts: true,
            instrument_call_targets: vec![],
        }
    }

    #[must_use]
    pub fn without_hitcounts(filter: QemuInstrumentationFilter) -> Self {
        Self {
            filter,
            use_hitcounts: false,
            instrument_call_targets: vec![],
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.filter.allowed(addr)
    }

    #[must_use]
    pub fn add_custom_call_target(&mut self, v: CustomCall) {
        self.instrument_call_targets.push(v);
    }
    /*
        pub fn get_instrument_call_targets(&self) -> Vec<CustomCall> {
            self.instrument_call_targets
        }
    */
}

impl Default for QemuEdgeCoverageClassicHelper {
    fn default() -> Self {
        Self::new(QemuInstrumentationFilter::None)
    }
}

impl HasInstrumentationFilter for QemuEdgeCoverageClassicHelper {
    fn filter(&self) -> &QemuInstrumentationFilter {
        &self.filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationFilter {
        &mut self.filter
    }
}

impl<S> QemuHelper<S> for QemuEdgeCoverageClassicHelper
where
    S: UsesInput,
    S: HasMetadata,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = false;

    fn first_exec<QT>(&self, hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        if self.use_hitcounts {
            hooks.blocks(
                Hook::Function(gen_hashed_block_ids::<QT, S>),
                Hook::Empty,
                Hook::Raw(trace_block_transition_hitcount),
            );
        } else {
            hooks.blocks(
                Hook::Function(gen_hashed_block_ids::<QT, S>),
                Hook::Empty,
                Hook::Raw(trace_block_transition_single),
            );
        }
        #[cfg(emulation_mode = "usermode")]
        if self.instrument_call_targets.len() > 0 {
            hooks.blocks(
                Hook::Function(QemuCustomCallHelper::gen_blocks_custom_calls::<QT, S>),
                Hook::Empty,
                Hook::Empty,
            );
        }
    }
}

thread_local!(static PREV_LOC : UnsafeCell<u64> = UnsafeCell::new(0));

pub fn gen_unique_edge_ids<QT, S>(
    hooks: &mut QemuHooks<QT, S>,
    state: Option<&mut S>,
    src: GuestAddr,
    dest: GuestAddr,
) -> Option<u64>
where
    S: HasMetadata,
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    if let Some(h) = hooks.helpers().match_first_type::<QemuEdgeCoverageHelper>() {
        if !h.must_instrument(src) && !h.must_instrument(dest) {
            return None;
        }
    }
    let state = state.expect("The gen_unique_edge_ids hook works only for in-process fuzzing");
    if state.metadata_map().get::<QemuEdgesMapMetadata>().is_none() {
        state.add_metadata(QemuEdgesMapMetadata::new());
    }
    let meta = state
        .metadata_map_mut()
        .get_mut::<QemuEdgesMapMetadata>()
        .unwrap();

    match meta.map.entry((src, dest)) {
        Entry::Occupied(e) => {
            let id = *e.get();
            let nxt = (id as usize + 1) & (EDGES_MAP_SIZE - 1);
            unsafe {
                MAX_EDGES_NUM = max(MAX_EDGES_NUM, nxt);
            }
            Some(id)
        }
        Entry::Vacant(e) => {
            let id = meta.current_id;
            e.insert(id);
            meta.current_id = (id + 1) & (EDGES_MAP_SIZE as u64 - 1);
            unsafe {
                MAX_EDGES_NUM = meta.current_id as usize;
            }
            // GuestAddress is u32 for 32 bit guests
            #[allow(clippy::unnecessary_cast)]
            Some(id as u64)
        }
    }
}

pub extern "C" fn trace_edge_hitcount(_: *const (), id: u64) {
    unsafe {
        EDGES_MAP[id as usize] = EDGES_MAP[id as usize].wrapping_add(1);
    }
}

pub extern "C" fn trace_edge_single(_: *const (), id: u64) {
    unsafe {
        EDGES_MAP[id as usize] = 1;
    }
}

pub fn gen_hashed_edge_ids<QT, S>(
    hooks: &mut QemuHooks<QT, S>,
    _state: Option<&mut S>,
    src: GuestAddr,
    dest: GuestAddr,
) -> Option<u64>
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    if let Some(h) = hooks
        .helpers()
        .match_first_type::<QemuEdgeCoverageChildHelper>()
    {
        if !h.must_instrument(src) && !h.must_instrument(dest) {
            return None;
        }
    }
    // GuestAddress is u32 for 32 bit guests
    #[allow(clippy::unnecessary_cast)]
    Some((hash_me(src as u64) ^ hash_me(dest as u64)) & (unsafe { EDGES_MAP_PTR_NUM } as u64 - 1))
}

pub extern "C" fn trace_edge_hitcount_ptr(_: *const (), id: u64) {
    unsafe {
        let ptr = EDGES_MAP_PTR.add(id as usize);
        *ptr = (*ptr).wrapping_add(1);
    }
}

pub extern "C" fn trace_edge_single_ptr(_: *const (), id: u64) {
    unsafe {
        let ptr = EDGES_MAP_PTR.add(id as usize);
        *ptr = 1;
    }
}

/*
pub fn gen_addr_block_ids<QT, S>(
    _hooks: &mut QemuHooks<QT, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
) -> Option<u64>
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    // GuestAddress is u32 for 32 bit guests
    #[allow(clippy::unnecessary_cast)]
    Some(pc as u64)
}
*/

#[derive(Debug)]
pub struct QemuCustomCallHelper {
    cs: Capstone,
}

#[cfg(emulation_mode = "usermode")]
impl QemuCustomCallHelper {
    fn gen_blocks_custom_calls<QT, S>(
        hooks: &mut QemuHooks<QT, S>,
        _state: Option<&mut S>,
        pc: GuestAddr,
    ) -> Option<u64>
    where
        S: UsesInput,
        QT: QemuHelperTuple<S>,
    {
        println!("gen_blocks_custom_calls");
        /*
                if let Some(_h) = hooks.helpers_mut().match_first_type_mut::<Self>() {

                    //            if !_h.must_instrument(pc) {
                    //                return None;
                    //            }

                    #[cfg(cpu_target = "arm")]
                    h.cs.set_mode(if pc & 1 == 1 {
                        capstone::arch::arm::ArchMode::Thumb.into()
                    } else {
                        capstone::arch::arm::ArchMode::Arm.into()
                    })
                    .unwrap();
                }

                let emu = hooks.emulator();

                if let Some(h) = hooks.helpers().match_first_type::<Self>() {
                    #[allow(unused_mut)]
                    let mut code = { unsafe { std::slice::from_raw_parts(emu.g2h(pc), 512) } };

                    let mut iaddr = pc;

                    'disasm: while let Ok(insns) = h.cs.disasm_count(code, iaddr.into(), 1) {
                        if insns.is_empty() {
                            break;
                        }
                        let insn = insns.first().unwrap();
                        let insn_detail: InsnDetail = h.cs.insn_detail(insn).unwrap();
                        for detail in insn_detail.groups() {
                            match u32::from(detail.0) {
                                capstone::InsnGroupType::CS_GRP_CALL => {
                                    //                           let addr = detail.1;
                                    let mut instrument_call = 0;
                                    let instrument_call_targets = h.get_instrument_call_targets();
                                    for targets in instrument_call_targets {
                                        //                              if targets.guest_addr == addr {
                                        println!("TODO!!");
                                        //emu.set_hook(k, insn.address() as GuestAddr, on_call, false);
                                        break;
                                        //                              }
                                    }
                                }
                                capstone::InsnGroupType::CS_GRP_RET
                                | capstone::InsnGroupType::CS_GRP_INVALID
                                | capstone::InsnGroupType::CS_GRP_JUMP
                                | capstone::InsnGroupType::CS_GRP_IRET
                                | capstone::InsnGroupType::CS_GRP_PRIVILEGE => {
                                    break 'disasm;
                                }
                                _ => {}
                            }
                        }

                        iaddr += insn.bytes().len() as GuestAddr;

                        unsafe {
                            code = std::slice::from_raw_parts(emu.g2h(iaddr), 512);
                        }
                    }
                }
        */
        None
    }
}

pub fn gen_hashed_block_ids<QT, S>(
    hooks: &mut QemuHooks<QT, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
) -> Option<u64>
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    if let Some(h) = hooks
        .helpers()
        .match_first_type::<QemuEdgeCoverageClassicHelper>()
    {
        if !h.must_instrument(pc) {
            return None;
        }
    }
    // GuestAddress is u32 for 32 bit guests
    #[allow(clippy::unnecessary_cast)]
    Some(hash_me(pc as u64))
}

pub extern "C" fn trace_block_transition_hitcount(_: *const (), id: u64) {
    unsafe {
        PREV_LOC.with(|prev_loc| {
            let x = ((*prev_loc.get() ^ id) as usize) & (EDGES_MAP_PTR_NUM - 1);
            let entry = EDGES_MAP_PTR.add(x);
            *entry = (*entry).wrapping_add(1);
            *prev_loc.get() = id.overflowing_shr(1).0;
        });
    }
}

pub extern "C" fn trace_block_transition_single(_: *const (), id: u64) {
    unsafe {
        PREV_LOC.with(|prev_loc| {
            let x = ((*prev_loc.get() ^ id) as usize) & (EDGES_MAP_PTR_NUM - 1);
            let entry = EDGES_MAP_PTR.add(x);
            *entry = 1;
            *prev_loc.get() = id.overflowing_shr(1).0;
        });
    }
}

/*
#[cfg(emulation_mode = "usermode")]
impl<S> QemuHelper<S> for QemuCmpLogRoutinesHelper
pub fn
*/
