use std::{collections::HashMap, env, fs, ops::RangeInclusive, path::Path, sync::LazyLock};

use build_target::{Arch, Os, PointerWidth, target_arch, target_os, target_pointer_width};
use rand::Rng;

// Default Linux/i386 mapping on i386 machine
// (addresses starting with 0xc0000000 are reserved
// for kernel and thus not sanitized):
// || `[0x38000000, 0xbfffffff]` || HighMem    ||
// || `[0x27000000, 0x37ffffff]` || HighShadow ||
// || `[0x24000000, 0x26ffffff]` || ShadowGap  ||
// || `[0x20000000, 0x23ffffff]` || LowShadow  ||
// || `[0x00000000, 0x1fffffff]` || LowMem     ||
const DEFAULT_32B_LAYOUT: TargetShadowLayout = TargetShadowLayout {
    high_mem: 0x38000000..=0xbfffffff,
    high_shadow: 0x27000000..=0x37ffffff,
    shadow_gap: 0x24000000..=0x26ffffff,
    low_shadow: 0x20000000..=0x23ffffff,
    low_mem: 0x00000000..=0x1fffffff,
};

// Typical shadow mapping on Linux/x86_64 with SHADOW_OFFSET == 0x00007fff8000:
// || `[0x10007fff8000, 0x7fffffffffff]` || HighMem    ||
// || `[0x02008fff7000, 0x10007fff7fff]` || HighShadow ||
// || `[0x00008fff7000, 0x02008fff6fff]` || ShadowGap  ||
// || `[0x00007fff8000, 0x00008fff6fff]` || LowShadow  ||
// || `[0x000000000000, 0x00007fff7fff]` || LowMem     ||
const DEFAULT_64B_LAYOUT: TargetShadowLayout = TargetShadowLayout {
    high_mem: 0x10007fff8000..=0x7fffffffffff,
    high_shadow: 0x02008fff7000..=0x10007fff7fff,
    shadow_gap: 0x00008fff7000..=0x02008fff6fff,
    low_shadow: 0x00007fff8000..=0x00008fff6fff,
    low_mem: 0x000000000000..=0x00007fff7fff,
};

#[expect(clippy::type_complexity)]
static SPECIFIC_LAYOUTS: LazyLock<HashMap<(Arch, Option<Vma>, Os), TargetShadowLayout>> =
    LazyLock::new(|| {
        let mut layouts = HashMap::new();

        // Typical shadow mapping on Linux/x86_64 with SHADOW_OFFSET == 0x00007fff8000:
        // || `[0x10007fff8000, 0x7fffffffffff]` || HighMem    ||
        // || `[0x02008fff7000, 0x10007fff7fff]` || HighShadow ||
        // || `[0x00008fff7000, 0x02008fff6fff]` || ShadowGap  ||
        // || `[0x00007fff8000, 0x00008fff6fff]` || LowShadow  ||
        // || `[0x000000000000, 0x00007fff7fff]` || LowMem     ||
        layouts.insert((Arch::X86_64, None, Os::Linux), DEFAULT_64B_LAYOUT.clone());

        // Default Linux/i386 mapping on i386 machine
        // (addresses starting with 0xc0000000 are reserved
        // for kernel and thus not sanitized):
        // || `[0x38000000, 0xbfffffff]` || HighMem    ||
        // || `[0x27000000, 0x37ffffff]` || HighShadow ||
        // || `[0x24000000, 0x26ffffff]` || ShadowGap  ||
        // || `[0x20000000, 0x23ffffff]` || LowShadow  ||
        // || `[0x00000000, 0x1fffffff]` || LowMem     ||
        layouts.insert((Arch::X86, None, Os::Linux), DEFAULT_32B_LAYOUT.clone());

        // Default Linux/AArch64 (48-bit VMA) mapping:
        // || `[0x201000000000, 0xffffffffffff]` || HighMem    || 229312GB
        // || `[0x041200000000, 0x200fffffffff]` || HighShadow || 28664GB
        // || `[0x001200000000, 0x0411ffffffff]` || ShadowGap  || 4096GB
        // || `[0x001000000000, 0x0011ffffffff]` || LowShadow  || 8GB
        // || `[0x000000000000, 0x000fffffffff]` || LowMem     || 64GB
        layouts.insert(
            (Arch::AArch64, Some(Vma::Vma48), Os::Linux),
            TargetShadowLayout {
                high_mem: 0x201000000000..=0xffffffffffff,
                high_shadow: 0x041200000000..=0x200fffffffff,
                shadow_gap: 0x001200000000..=0x0411ffffffff,
                low_shadow: 0x001000000000..=0x0011ffffffff,
                low_mem: 0x000000000000..=0x000fffffffff,
            },
        );

        layouts
    });

const LAYOUT_TEMPLATE: &str = r#"
use crate::GuestAddr;
use super::ShadowLayout;

#[derive(Debug)]
pub struct DefaultShadowLayout;

impl ShadowLayout for DefaultShadowLayout {
    const SHADOW_OFFSET: usize = {shadow_offset};
    const LOW_MEM_OFFSET: GuestAddr = {low_mem_offset};
    const LOW_MEM_SIZE: usize = {low_mem_size};
    const LOW_SHADOW_OFFSET: GuestAddr = {low_shadow_offset};
    const LOW_SHADOW_SIZE: usize = {low_shadow_size};
    const HIGH_SHADOW_OFFSET: GuestAddr = {high_shadow_offset};
    const HIGH_SHADOW_SIZE: usize = {high_shadow_size};
    const HIGH_MEM_OFFSET: GuestAddr = {high_mem_offset};
    const HIGH_MEM_SIZE: usize = {high_mem_size};

    const ALLOC_ALIGN_POW: usize = 3;
    const ALLOC_ALIGN_SIZE: usize = 1 << Self::ALLOC_ALIGN_POW;
}
"#;

#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash)]
pub enum Vma {
    Vma39,
    Vma42,
    Vma47,
    Vma48,
    Vma52,
}

#[derive(Clone, Debug)]
pub struct TargetShadowLayout {
    high_mem: RangeInclusive<u64>,
    high_shadow: RangeInclusive<u64>,
    shadow_gap: RangeInclusive<u64>,
    low_shadow: RangeInclusive<u64>,
    low_mem: RangeInclusive<u64>,
}

impl TargetShadowLayout {
    pub fn low_mem_offset(&self) -> String {
        format!("{:#x}", self.low_mem.start())
    }

    pub fn low_mem_size(&self) -> String {
        format!("{:#x}", self.low_mem.clone().count())
    }

    pub fn low_shadow_offset(&self) -> String {
        format!("{:#x}", self.low_shadow.start())
    }

    pub fn low_shadow_size(&self) -> String {
        format!("{:#x}", self.low_shadow.clone().count())
    }

    pub fn shadow_gap_offset(&self) -> String {
        format!("{:#x}", self.shadow_gap.start())
    }

    pub fn shadow_gap_size(&self) -> String {
        format!("{:#x}", self.shadow_gap.clone().count())
    }

    pub fn high_mem_offset(&self) -> String {
        format!("{:#x}", self.high_mem.start())
    }

    pub fn high_mem_size(&self) -> String {
        format!("{:#x}", self.high_mem.clone().count())
    }

    pub fn high_shadow_offset(&self) -> String {
        format!("{:#x}", self.high_shadow.start())
    }

    pub fn high_shadow_size(&self) -> String {
        format!("{:#x}", self.high_shadow.clone().count())
    }
}

fn find_max_vaddr_bits<const NB_TRIES: usize>() -> usize {
    let mut rng = rand::rng();
    let page_size = page_size::get();

    assert_eq!(page_size.count_ones(), 1);

    let mut bits_min: usize = page_size.trailing_zeros() as usize; // log2(page_size)
    let mut bits_max: usize = usize::BITS as usize; // size in bits of max addressable memory

    while bits_min != bits_max {
        let bits_current = (bits_min + bits_max) / 2;

        let mut is_mappable = false;
        for _ in 0..NB_TRIES {
            let current_addr_min = 1usize << (bits_current - 1);
            let current_addr_max = 1usize << bits_current;
            let current_addr_sz = current_addr_max - current_addr_min;

            assert_eq!(current_addr_sz % page_size, 0);

            let max_page = current_addr_sz / page_size;

            let rdm_page = rng.random_range(0..max_page);

            let map_addr = current_addr_min + (page_size * rdm_page);

            let map_addr_ptr = unsafe {
                libc::mmap(
                    map_addr as *mut libc::c_void,
                    page_size,
                    libc::PROT_READ,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                    -1,
                    0,
                )
            };

            if map_addr_ptr != (-1isize as *mut libc::c_void) {
                unsafe {
                    libc::munmap(map_addr_ptr, page_size);
                }
                is_mappable = true;
                break;
            }
        }

        if is_mappable {
            bits_min = bits_current + 1;
        } else {
            bits_max = bits_current;
        }
    }

    bits_min
}

fn get_host_vma() -> Vma {
    match find_max_vaddr_bits::<8>() {
        39 => Vma::Vma39,
        42 => Vma::Vma42,
        47 => Vma::Vma47,
        48 => Vma::Vma48,
        52 => Vma::Vma52,
        val => {
            panic!("Dynamic layout does not support VMA with {val} bits")
        }
    }
}

fn guess_vma(arch: &Arch) -> Option<Vma> {
    match arch {
        Arch::AArch64 => Some(get_host_vma()),
        _ => None,
    }
}

fn get_layout() -> TargetShadowLayout {
    let arch = target_arch();
    let vma = guess_vma(&arch);
    let os = target_os();

    println!("cargo:warning=Generating layout for environment: {arch} - VMA {vma:?} - {os}.");

    if let Some(specific_layout) = SPECIFIC_LAYOUTS.get(&(arch.clone(), vma, os.clone())) {
        specific_layout.clone()
    } else {
        let (default_layout, nb_bits) = match target_pointer_width() {
            PointerWidth::U32 => (DEFAULT_32B_LAYOUT.clone(), 32),
            PointerWidth::U64 => (DEFAULT_64B_LAYOUT.clone(), 64),
            _ => {
                panic!("Could not find the right layout for {arch:?} (VMA {vma:?}) {os:?}")
            }
        };

        println!("cargo:warning=Using default layout for {nb_bits} bits architectures.");

        default_layout
    }
}

fn main() {
    //#[cfg(all(feature = "syscalls", not(target_os = "linux")))]
    println!("cargo:warning=The feature `linux` can only be used on Linux!");

    println!("cargo:rerun-if-changed=cc/include/hooks.h");
    println!("cargo:rerun-if-changed=cc/include/trace.h");
    println!("cargo:rerun-if-changed=cc/src/asprintf.c");
    println!("cargo:rerun-if-changed=cc/src/log.c");
    println!("cargo:rerun-if-changed=cc/src/vasprintf.c");

    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() != "windows" {
        cc::Build::new()
            .define("_GNU_SOURCE", None)
            .opt_level(3)
            .flag("-Werror")
            .flag("-fno-stack-protector")
            .flag("-U_FORTIFY_SOURCE")
            .flag("-D_FORTIFY_SOURCE=0")
            .flag("-ffunction-sections")
            .include("cc/include/")
            .file("cc/src/asprintf.c")
            .compile("asprintf");

        cc::Build::new()
            .define("_GNU_SOURCE", None)
            .opt_level(3)
            .flag("-Werror")
            .flag("-fno-stack-protector")
            .flag("-U_FORTIFY_SOURCE")
            .flag("-D_FORTIFY_SOURCE=0")
            .flag("-ffunction-sections")
            .include("cc/include/")
            .file("cc/src/vasprintf.c")
            .compile("vasprintf");
    }

    cc::Build::new()
        .define("_GNU_SOURCE", None)
        .opt_level(3)
        .flag("-Werror")
        .flag("-fno-stack-protector")
        .flag("-U_FORTIFY_SOURCE")
        .flag("-D_FORTIFY_SOURCE=0")
        .flag("-ffunction-sections")
        .include("cc/include/")
        .file("cc/src/log.c")
        .compile("log");

    let layout = get_layout();

    let gen_layout = LAYOUT_TEMPLATE
        .to_string()
        .replace("{shadow_offset}", &layout.low_shadow_offset())
        .replace("{low_mem_offset}", &layout.low_mem_offset())
        .replace("{low_mem_size}", &layout.low_mem_size())
        .replace("{low_shadow_offset}", &layout.low_shadow_offset())
        .replace("{low_shadow_size}", &layout.low_shadow_size())
        .replace("{high_shadow_offset}", &layout.high_shadow_offset())
        .replace("{high_shadow_size}", &layout.high_shadow_size())
        .replace("{high_mem_offset}", &layout.high_mem_offset())
        .replace("{high_mem_size}", &layout.high_mem_size());

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("gen_layout.rs");
    fs::write(&dest_path, gen_layout).unwrap();
}
