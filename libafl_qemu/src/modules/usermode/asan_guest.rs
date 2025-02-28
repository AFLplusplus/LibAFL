#![allow(clippy::cast_possible_wrap)]

use std::{
    env,
    fmt::{self, Debug, Formatter},
    fs,
    path::PathBuf,
};

use libafl_qemu_sys::{GuestAddr, MapInfo};

#[cfg(not(feature = "clippy"))]
use crate::sys::libafl_tcg_gen_asan;
use crate::{
    QemuParams,
    emu::EmulatorModules,
    modules::{
        AddressFilter, EmulatorModule, EmulatorModuleTuple,
        utils::filters::{HasAddressFilter, StdAddressFilter},
    },
    qemu::{Hook, MemAccessInfo, Qemu},
    sys::TCGTemp,
};

#[derive(Clone)]
struct QemuAsanGuestMapping {
    start: GuestAddr,
    end: GuestAddr,
    path: String,
}

impl Debug for QemuAsanGuestMapping {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:016x}-0x{:016x} {}", self.start, self.end, self.path)
    }
}

impl From<&MapInfo> for QemuAsanGuestMapping {
    fn from(map: &MapInfo) -> QemuAsanGuestMapping {
        let path = map.path().map(ToString::to_string).unwrap_or_default();
        let start = map.start();
        let end = map.end();
        QemuAsanGuestMapping { start, end, path }
    }
}

#[derive(Debug)]
pub struct AsanGuestModule<F> {
    env: Vec<(String, String)>,
    filter: F,
    mappings: Option<Vec<QemuAsanGuestMapping>>,
    asan_lib: Option<String>,
}

#[cfg(any(
    cpu_target = "aarch64",
    cpu_target = "x86_64",
    cpu_target = "riscv64",
    feature = "clippy"
))]
impl<F> AsanGuestModule<F> {
    const HIGH_SHADOW_START: GuestAddr = 0x02008fff7000;
    const HIGH_SHADOW_END: GuestAddr = 0x10007fff7fff;
    const LOW_SHADOW_START: GuestAddr = 0x00007fff8000;
    const LOW_SHADOW_END: GuestAddr = 0x00008fff6fff;
}

#[cfg(any(
    cpu_target = "arm",
    cpu_target = "i386",
    cpu_target = "mips",
    cpu_target = "ppc",
    cpu_target = "riscv32",
))]
impl<F> AsanGuestModule<F> {
    const HIGH_SHADOW_START: GuestAddr = 0x28000000;
    const HIGH_SHADOW_END: GuestAddr = 0x3fffffff;
    const LOW_SHADOW_START: GuestAddr = 0x20000000;
    const LOW_SHADOW_END: GuestAddr = 0x23ffffff;
}

impl AsanGuestModule<StdAddressFilter> {
    #[must_use]
    pub fn default(env: &[(String, String)]) -> Self {
        Self::new(env, StdAddressFilter::default())
    }
}

impl<F> AsanGuestModule<F>
where
    F: AddressFilter,
{
    #[must_use]
    pub fn new(env: &[(String, String)], filter: F) -> Self {
        Self {
            env: env.to_vec(),
            filter,
            mappings: None,
            asan_lib: None,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.filter.allowed(&addr)
    }
}

#[allow(clippy::needless_pass_by_value)] // no longer a problem with nightly
fn gen_readwrite_guest_asan<ET, F, I, S>(
    _qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
    addr: *mut TCGTemp,
    info: MemAccessInfo,
) -> Option<u64>
where
    ET: EmulatorModuleTuple<I, S>,
    F: AddressFilter,
    I: Unpin,
    S: Unpin,
{
    let h = emulator_modules.get_mut::<AsanGuestModule<F>>().unwrap();
    if !h.must_instrument(pc) {
        return None;
    }

    /* Don't sanitize the sanitizer! */
    unsafe {
        if h.mappings
            .as_mut()
            .unwrap_unchecked()
            .iter()
            .any(|m| m.start <= pc && pc < m.end)
        {
            return None;
        }
    }

    let size = info.size();

    /* TODO - If our size is > 8 then do things via a runtime callback */
    assert!(size <= 8, "I shouldn't be here!");

    unsafe {
        libafl_tcg_gen_asan(addr, size);
    }

    None
}

#[cfg(feature = "clippy")]
#[expect(unused_variables)]
unsafe fn libafl_tcg_gen_asan(addr: *mut TCGTemp, size: usize) {}

#[allow(clippy::needless_pass_by_value)] // no longer a problem with nightly
fn guest_trace_error_asan<ET, I, S>(
    _qemu: Qemu,
    _emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    _id: u64,
    _pc: GuestAddr,
    _addr: GuestAddr,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    panic!("I really shouldn't be here");
}

#[allow(clippy::needless_pass_by_value)] // no longer a problem with nightly
fn guest_trace_error_n_asan<ET, I, S>(
    _qemu: Qemu,
    _emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    _id: u64,
    _pc: GuestAddr,
    _addr: GuestAddr,
    _n: usize,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    panic!("I really shouldn't be here either");
}

impl<F, I, S> EmulatorModule<I, S> for AsanGuestModule<F>
where
    F: AddressFilter,
    I: Unpin,
    S: Unpin,
{
    fn pre_qemu_init<ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        qemu_params: &mut QemuParams,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        let mut args = qemu_params.to_cli();

        let current = env::current_exe().unwrap();
        let asan_lib = fs::canonicalize(current)
            .unwrap()
            .parent()
            .unwrap()
            .join("libgasan.so");

        let asan_lib = env::var_os("CUSTOM_ASAN_PATH")
            .map_or(asan_lib, |x| PathBuf::from(x.to_string_lossy().to_string()));

        assert!(
            asan_lib.as_path().exists(),
            "The ASAN library doesn't exist: {asan_lib:#?}"
        );

        let asan_lib = asan_lib
            .to_str()
            .expect("The path to the asan lib is invalid")
            .to_string();

        println!("Loading ASAN: {asan_lib:}");

        let add_asan =
            |e: &str| "LD_PRELOAD=".to_string() + &asan_lib + " " + &e["LD_PRELOAD=".len()..];

        let mut added = false;
        for (k, v) in &mut self.env {
            if k == "QEMU_SET_ENV" {
                let mut new_v = vec![];
                for e in v.split(',') {
                    if e.starts_with("LD_PRELOAD=") {
                        added = true;
                        new_v.push(add_asan(e));
                    } else {
                        new_v.push(e.to_string());
                    }
                }
                *v = new_v.join(",");
            }
        }
        for i in 0..args.len() {
            if args[i] == "-E" && i + 1 < args.len() && args[i + 1].starts_with("LD_PRELOAD=") {
                added = true;
                args[i + 1] = add_asan(&args[i + 1]);
            }
        }

        if !added {
            args.insert(1, "LD_PRELOAD=".to_string() + &asan_lib);
            args.insert(1, "-E".into());
        }

        if env::var("QASAN_DEBUG").is_ok() {
            args.push("-E".into());
            args.push("QASAN_DEBUG=1".into());
        }

        if env::var("QASAN_LOG").is_ok() {
            args.push("-E".into());
            args.push("QASAN_LOG=1".into());
        }

        *qemu_params = QemuParams::Cli(args);

        self.asan_lib = Some(asan_lib);
    }

    fn post_qemu_init<ET>(&mut self, _qemu: Qemu, _emulator_modules: &mut EmulatorModules<ET, I, S>)
    where
        ET: EmulatorModuleTuple<I, S>,
    {
    }

    fn first_exec<ET>(
        &mut self,
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
        I: Unpin,
        S: Unpin,
    {
        for mapping in qemu.mappings() {
            println!("mapping: {mapping:#?}");
        }

        let mappings = qemu
            .mappings()
            .map(|m| QemuAsanGuestMapping::from(&m))
            .collect::<Vec<QemuAsanGuestMapping>>();

        for mapping in &mappings {
            println!("guest mapping: {mapping:#?}");
        }

        mappings
            .iter()
            .find(|m| m.start <= Self::HIGH_SHADOW_START && m.end > Self::HIGH_SHADOW_END)
            .expect("HighShadow not found, confirm ASAN DSO is loaded in the guest");

        mappings
            .iter()
            .find(|m| m.start <= Self::LOW_SHADOW_START && m.end > Self::LOW_SHADOW_END)
            .expect("LowShadow not found, confirm ASAN DSO is loaded in the guest");

        let mappings = mappings
            .iter()
            .filter(|m| &m.path == self.asan_lib.as_ref().unwrap())
            .cloned()
            .collect::<Vec<QemuAsanGuestMapping>>();

        for mapping in &mappings {
            println!("asan mapping: {mapping:#?}");
        }

        emulator_modules.reads(
            Hook::Function(gen_readwrite_guest_asan::<ET, F, I, S>),
            Hook::Function(guest_trace_error_asan::<ET, I, S>),
            Hook::Function(guest_trace_error_asan::<ET, I, S>),
            Hook::Function(guest_trace_error_asan::<ET, I, S>),
            Hook::Function(guest_trace_error_asan::<ET, I, S>),
            Hook::Function(guest_trace_error_n_asan::<ET, I, S>),
        );

        emulator_modules.writes(
            Hook::Function(gen_readwrite_guest_asan::<ET, F, I, S>),
            Hook::Function(guest_trace_error_asan::<ET, I, S>),
            Hook::Function(guest_trace_error_asan::<ET, I, S>),
            Hook::Function(guest_trace_error_asan::<ET, I, S>),
            Hook::Function(guest_trace_error_asan::<ET, I, S>),
            Hook::Function(guest_trace_error_n_asan::<ET, I, S>),
        );
    }
}

impl<F> HasAddressFilter for AsanGuestModule<F>
where
    F: AddressFilter,
{
    type AddressFilter = F;

    fn address_filter(&self) -> &Self::AddressFilter {
        &self.filter
    }

    fn address_filter_mut(&mut self) -> &mut Self::AddressFilter {
        &mut self.filter
    }
}
