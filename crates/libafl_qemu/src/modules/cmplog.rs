#[cfg(feature = "usermode")]
use capstone::{Capstone, InsnDetail, arch::BuildsCapstone};
use hashbrown::HashMap;
use libafl::HasMetadata;
use libafl_bolts::hash_64_fast;
use libafl_qemu_sys::GuestAddr;
pub use libafl_targets::{
    CMPLOG_MAP_H, CMPLOG_MAP_PTR, CMPLOG_MAP_SIZE, CMPLOG_MAP_W, CmpLogMap, CmpLogObserver,
    cmps::{
        __libafl_targets_cmplog_instructions, __libafl_targets_cmplog_routines, CMPLOG_ENABLED,
    },
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "usermode")]
use crate::capstone;
#[cfg(feature = "systemmode")]
use crate::modules::utils::filters::{HasPageFilter, NOP_PAGE_FILTER, NopPageFilter};
use crate::{
    Qemu,
    emu::EmulatorModules,
    modules::{
        AddressFilter, EmulatorModule, EmulatorModuleTuple,
        utils::filters::{HasAddressFilter, StdAddressFilter},
    },
    qemu::Hook,
};

#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct QemuCmpsMapMetadata {
    pub map: HashMap<u64, u64>,
    pub current_id: u64,
}

impl QemuCmpsMapMetadata {
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            current_id: 0,
        }
    }
}

libafl_bolts::impl_serdeany!(QemuCmpsMapMetadata);

#[derive(Debug)]
pub struct CmpLogModule {
    address_filter: StdAddressFilter,
}

impl CmpLogModule {
    #[must_use]
    pub fn new(address_filter: StdAddressFilter) -> Self {
        Self { address_filter }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.address_filter.allowed(&addr)
    }
}

impl Default for CmpLogModule {
    fn default() -> Self {
        Self::new(StdAddressFilter::default())
    }
}

impl<I, S> EmulatorModule<I, S> for CmpLogModule
where
    I: Unpin,
    S: Unpin + HasMetadata,
{
    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        emulator_modules.cmps(
            Hook::Function(gen_unique_cmp_ids::<ET, I, S>),
            Hook::Raw(trace_cmp1_cmplog),
            Hook::Raw(trace_cmp2_cmplog),
            Hook::Raw(trace_cmp4_cmplog),
            Hook::Raw(trace_cmp8_cmplog),
        );
    }
}

impl HasAddressFilter for CmpLogModule {
    type AddressFilter = StdAddressFilter;

    fn address_filter(&self) -> &Self::AddressFilter {
        &self.address_filter
    }

    fn address_filter_mut(&mut self) -> &mut Self::AddressFilter {
        &mut self.address_filter
    }
}

#[cfg(feature = "systemmode")]
impl HasPageFilter for CmpLogModule {
    type PageFilter = NopPageFilter;

    fn page_filter(&self) -> &Self::PageFilter {
        &NopPageFilter
    }

    fn page_filter_mut(&mut self) -> &mut Self::PageFilter {
        unsafe { (&raw mut NOP_PAGE_FILTER).as_mut().unwrap().get_mut() }
    }
}

#[derive(Debug)]
pub struct CmpLogChildModule {
    address_filter: StdAddressFilter,
}

impl CmpLogChildModule {
    #[must_use]
    pub fn new(address_filter: StdAddressFilter) -> Self {
        Self { address_filter }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.address_filter.allowed(&addr)
    }
}

impl Default for CmpLogChildModule {
    fn default() -> Self {
        Self::new(StdAddressFilter::default())
    }
}

impl<I, S> EmulatorModule<I, S> for CmpLogChildModule
where
    I: Unpin,
    S: Unpin + HasMetadata,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = false;

    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        emulator_modules.cmps(
            Hook::Function(gen_hashed_cmp_ids::<ET, I, S>),
            Hook::Raw(trace_cmp1_cmplog),
            Hook::Raw(trace_cmp2_cmplog),
            Hook::Raw(trace_cmp4_cmplog),
            Hook::Raw(trace_cmp8_cmplog),
        );
    }
}

impl HasAddressFilter for CmpLogChildModule {
    type AddressFilter = StdAddressFilter;

    fn address_filter(&self) -> &Self::AddressFilter {
        &self.address_filter
    }

    fn address_filter_mut(&mut self) -> &mut Self::AddressFilter {
        &mut self.address_filter
    }
}

#[cfg(feature = "systemmode")]
impl HasPageFilter for CmpLogChildModule {
    type PageFilter = NopPageFilter;

    fn page_filter(&self) -> &Self::PageFilter {
        &NopPageFilter
    }

    fn page_filter_mut(&mut self) -> &mut Self::PageFilter {
        unsafe { (&raw mut NOP_PAGE_FILTER).as_mut().unwrap().get_mut() }
    }
}

pub fn gen_unique_cmp_ids<ET, I, S>(
    _qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    state: Option<&mut S>,
    pc: GuestAddr,
    _size: usize,
) -> Option<u64>
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin + HasMetadata,
{
    if let Some(h) = emulator_modules.get::<CmpLogModule>() {
        if !h.must_instrument(pc) {
            return None;
        }
    }
    let state = state.expect("The gen_unique_cmp_ids hook works only for in-process fuzzing. Is the Executor initialized?");
    if state.metadata_map().get::<QemuCmpsMapMetadata>().is_none() {
        state.add_metadata(QemuCmpsMapMetadata::new());
    }
    let meta = state
        .metadata_map_mut()
        .get_mut::<QemuCmpsMapMetadata>()
        .unwrap();
    let id = meta.current_id as usize;

    Some(*meta.map.entry(pc.into()).or_insert_with(|| {
        meta.current_id = ((id + 1) & (CMPLOG_MAP_W - 1)) as u64;
        id as u64
    }))
}

#[allow(clippy::needless_pass_by_value)] // no longer a problem with nightly
pub fn gen_hashed_cmp_ids<ET, I, S>(
    _qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
    _size: usize,
) -> Option<u64>
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: HasMetadata + Unpin,
{
    if let Some(h) = emulator_modules.get::<CmpLogChildModule>() {
        if !h.must_instrument(pc) {
            return None;
        }
    }
    Some(hash_64_fast(pc.into()) & (CMPLOG_MAP_W as u64 - 1))
}

pub extern "C" fn trace_cmp1_cmplog(_: *const (), id: u64, v0: u8, v1: u8) {
    unsafe {
        __libafl_targets_cmplog_instructions(id as usize, 1, u64::from(v0), u64::from(v1));
    }
}

pub extern "C" fn trace_cmp2_cmplog(_: *const (), id: u64, v0: u16, v1: u16) {
    unsafe {
        __libafl_targets_cmplog_instructions(id as usize, 2, u64::from(v0), u64::from(v1));
    }
}

pub extern "C" fn trace_cmp4_cmplog(_: *const (), id: u64, v0: u32, v1: u32) {
    unsafe {
        __libafl_targets_cmplog_instructions(id as usize, 4, u64::from(v0), u64::from(v1));
    }
}

pub extern "C" fn trace_cmp8_cmplog(_: *const (), id: u64, v0: u64, v1: u64) {
    unsafe {
        __libafl_targets_cmplog_instructions(id as usize, 8, v0, v1);
    }
}

#[cfg(feature = "usermode")]
#[derive(Debug)]
pub struct CmpLogRoutinesModule {
    address_filter: StdAddressFilter,
    cs: Capstone,
}

#[cfg(feature = "usermode")]
impl CmpLogRoutinesModule {
    #[must_use]
    pub fn new(address_filter: StdAddressFilter) -> Self {
        Self {
            address_filter,
            cs: capstone().detail(true).build().unwrap(),
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.address_filter.allowed(&addr)
    }

    /// # Safety
    /// Dereferences k as pointer eventually.
    unsafe extern "C" fn on_call(k: u64, _pc: GuestAddr) {
        unsafe {
            if CMPLOG_ENABLED == 0 {
                return;
            }
        }

        let qemu = Qemu::get().unwrap();

        let a0: GuestAddr = qemu.read_function_argument(0).unwrap_or(0);
        let a1: GuestAddr = qemu.read_function_argument(1).unwrap_or(0);

        if a0 == 0 || a1 == 0 {
            return;
        }

        // if !emu.access_ok(VerifyAccess::Read, a0, 0x20) || !emu.access_ok(VerifyAccess::Read, a1, 0x20) { return; }

        unsafe {
            __libafl_targets_cmplog_routines(k as usize, qemu.g2h(a0), qemu.g2h(a1));
        }
    }

    #[allow(clippy::needless_pass_by_value)] // no longer a problem with nightly
    fn gen_blocks_calls<ET, I, S>(
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: Option<&mut S>,
        pc: GuestAddr,
    ) -> Option<u64>
    where
        ET: EmulatorModuleTuple<I, S>,
        I: Unpin,
        S: Unpin,
    {
        if let Some(h) = emulator_modules.get_mut::<Self>() {
            if !h.must_instrument(pc) {
                return None;
            }

            #[cfg(cpu_target = "arm")]
            h.cs.set_mode(if pc & 1 == 1 {
                capstone::arch::arm::ArchMode::Thumb.into()
            } else {
                capstone::arch::arm::ArchMode::Arm.into()
            })
            .unwrap();
        }

        if let Some(h) = emulator_modules.get::<Self>() {
            #[allow(unused_mut)] // cfg dependent
            let mut code = {
                #[cfg(feature = "usermode")]
                {
                    unsafe { std::slice::from_raw_parts(qemu.g2h(pc), 512) }
                }
                #[cfg(feature = "systemmode")]
                {
                    &mut [0; 512]
                }
            };
            #[cfg(feature = "systemmode")]
            {
                unsafe { qemu.read_mem(pc, code) }; // TODO handle faults
            }

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
                            let k = (hash_64_fast(pc.into())) & (CMPLOG_MAP_W as u64 - 1);
                            qemu.hooks().add_instruction_hooks(
                                k,
                                insn.address() as GuestAddr,
                                Self::on_call,
                                false,
                            );
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

                #[cfg(feature = "usermode")]
                {
                    code = unsafe { std::slice::from_raw_parts(qemu.g2h(iaddr), 512) };
                }
                #[cfg(feature = "systemmode")]
                {
                    unsafe {
                        qemu.read_mem(pc, code);
                    } // TODO handle faults
                }
            }
        }

        None
    }
}

#[cfg(feature = "usermode")]
impl<I, S> EmulatorModule<I, S> for CmpLogRoutinesModule
where
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
        emulator_modules.blocks(
            Hook::Function(Self::gen_blocks_calls::<ET, I, S>),
            Hook::Empty,
            Hook::Empty,
        );
    }
}

#[cfg(feature = "usermode")]
impl HasAddressFilter for CmpLogRoutinesModule {
    type AddressFilter = StdAddressFilter;
    #[cfg(feature = "systemmode")]
    type ModulePageFilter = NopPageFilter;

    fn address_filter(&self) -> &Self::AddressFilter {
        &self.address_filter
    }

    fn address_filter_mut(&mut self) -> &mut Self::AddressFilter {
        &mut self.address_filter
    }

    #[cfg(feature = "systemmode")]
    fn page_filter(&self) -> &Self::ModulePageFilter {
        &NopPageFilter
    }

    #[cfg(feature = "systemmode")]
    fn page_filter_mut(&mut self) -> &mut Self::ModulePageFilter {
        &mut NopPageFilter
    }
}
