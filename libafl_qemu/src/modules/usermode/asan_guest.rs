#![allow(clippy::cast_possible_wrap)]

use std::{env, fmt::Debug, fs, ops::Range, path::PathBuf};

use libafl_qemu_sys::{GuestAddr, MapInfo};

use super::IntervalSnapshotFilter;
#[cfg(not(feature = "clippy"))]
use crate::sys::libafl_tcg_gen_asan;
use crate::{
    QemuParams,
    emu::EmulatorModules,
    modules::{
        AddressFilter, EmulatorModule, EmulatorModuleTuple,
        snapshot::IntervalSnapshotFilters,
        utils::filters::{HasAddressFilter, StdAddressFilter},
    },
    qemu::{Hook, MemAccessInfo, Qemu},
    sys::TCGTemp,
};

#[derive(Debug)]
pub struct AsanGuestModule<F> {
    env: Vec<(String, String)>,
    filter: F,
    asan_lib: Option<String>,
    asan_mappings: Option<Vec<MapInfo>>,
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

    #[must_use]
    pub fn snapshot_filters() -> IntervalSnapshotFilters {
        IntervalSnapshotFilters::from(vec![IntervalSnapshotFilter::ZeroList(vec![
            Range {
                start: Self::LOW_SHADOW_START,
                end: Self::LOW_SHADOW_END + 1,
            },
            Range {
                start: Self::HIGH_SHADOW_START,
                end: Self::HIGH_SHADOW_END + 1,
            },
        ])])
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
            asan_lib: None,
            asan_mappings: None,
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
    if let Some(asan_mappings) = &h.asan_mappings {
        if asan_mappings
            .iter()
            .any(|m| m.start() <= pc && pc < m.end())
        {
            return None;
        }
    }

    let size = info.size();

    // TODO: Handle larger load/store operations
    unsafe {
        libafl_tcg_gen_asan(addr, size.min(8));
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

        // Let the use skip preloading the ASAN DSO. Maybe they want to use
        // their own implementation.
        let asan_lib = if env::var_os("SKIP_ASAN_LD_PRELOAD").is_none() {
            let current = env::current_exe().unwrap();
            let asan_lib = fs::canonicalize(current)
                .unwrap()
                .parent()
                .unwrap()
                .join("libafl_qemu_asan_guest.so");

            let asan_lib = env::var_os("CUSTOM_LIBAFL_QEMU_ASAN_PATH").map_or(asan_lib, |x| {
                fs::canonicalize(PathBuf::from(x.to_string_lossy().to_string())).unwrap()
            });

            assert!(
                asan_lib.as_path().exists(),
                "The ASAN library doesn't exist: {}",
                asan_lib.display()
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
            Some(asan_lib)
        } else {
            None
        };

        if env::var("LIBAFL_QEMU_ASAN_DEBUG").is_ok() {
            args.push("-E".into());
            args.push("LIBAFL_QEMU_ASAN_DEBUG=1".into());
        }

        if env::var("LIBAFL_QEMU_ASAN_LOG").is_ok() {
            args.push("-E".into());
            args.push("LIBAFL_QEMU_ASAN_LOG=1".into());
        }

        *qemu_params = QemuParams::Cli(args);

        self.asan_lib = asan_lib;
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
        let mappings = qemu.mappings().collect::<Vec<MapInfo>>();
        for mapping in &mappings {
            log::info!("mapping: {mapping:}");
        }

        let high_shadow = mappings
            .iter()
            .find(|m| m.start() <= Self::HIGH_SHADOW_START && m.end() > Self::HIGH_SHADOW_END)
            .expect("HighShadow not found, confirm ASAN DSO is loaded in the guest");
        log::info!("high_shadow: {high_shadow:}");

        let low_shadow = mappings
            .iter()
            .find(|m| m.start() <= Self::LOW_SHADOW_START && m.end() > Self::LOW_SHADOW_END)
            .expect("LowShadow not found, confirm ASAN DSO is loaded in the guest");
        log::info!("low_shadow: {low_shadow:}");

        if let Some(asan_lib) = &self.asan_lib {
            let asan_mappings = mappings
                .into_iter()
                .filter(|m| match m.path() {
                    Some(p) => p == asan_lib,
                    None => false,
                })
                .collect::<Vec<MapInfo>>();
            for m in &asan_mappings {
                log::info!("asan mapping: {m:}");
            }
            self.asan_mappings = Some(asan_mappings);
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
