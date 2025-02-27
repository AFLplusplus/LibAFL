//! Utils for addr2line

use std::{borrow::Cow, fmt::Write, fs};

use addr2line::{Loader, fallible_iterator::FallibleIterator};
use goblin::elf::dynamic::{DF_1_PIE, DT_FLAGS_1};
use hashbrown::HashMap;
use libafl_qemu_sys::GuestAddr;
use rangemap::RangeMap;

use crate::Qemu;
// (almost) Copy paste from addr2line/src/bin/addr2line.rs
fn print_function(name: Option<&str>, language: Option<addr2line::gimli::DwLang>) -> String {
    let ret = if let Some(name) = name {
        addr2line::demangle_auto(Cow::from(name), language).to_string()
    } else {
        "??".to_string()
    };
    // println!("{ret:?}");
    ret
}

/// check if this binary is pie (for 64bit binary only)
#[must_use]
pub fn is_pie(file: object::File<'_>) -> bool {
    let is_pie = match file {
        object::File::Elf64(elf) => {
            let mut is_pie = false;
            let table = elf.elf_section_table();
            let dyn_sec = table.dynamic(elf.endian(), elf.data());
            if let Ok(Some(d)) = dyn_sec {
                let arr = d.0;
                for v in arr {
                    if v.d_tag.get(elf.endian()) == DT_FLAGS_1
                        && v.d_val.get(elf.endian()) & DF_1_PIE == DF_1_PIE
                    {
                        is_pie = true;
                    }
                }
            }
            is_pie
        }
        _ => false,
    };

    is_pie
}

pub struct AddressResolver {
    ranges: RangeMap<GuestAddr, usize>,
    images: Vec<(String, Vec<u8>)>,
    resolvers: Vec<Option<(Loader, bool)>>,
}

impl AddressResolver {
    #[must_use]
    pub fn new(qemu: &Qemu) -> Self {
        let mut regions = HashMap::new();
        for region in qemu.mappings() {
            if let Some(path) = region.path() {
                let start = region.start();
                let end = region.end();
                let entry = regions.entry(path.to_owned()).or_insert(start..end);
                if start < entry.start {
                    *entry = start..entry.end;
                }
                if end > entry.end {
                    *entry = entry.start..end;
                }
            }
        }

        let mut resolvers = vec![];
        let mut images = vec![];
        let mut ranges: RangeMap<GuestAddr, usize> = RangeMap::new();

        for (path, rng) in regions {
            let data = fs::read(&path);
            if data.is_err() {
                continue;
            }
            let data = data.unwrap();
            let idx = images.len();
            images.push((path, data));
            ranges.insert(rng, idx);
        }

        for img in &images {
            if let Ok(obj) = object::read::File::parse(&*img.1) {
                let is_pie = is_pie(obj);

                let ctx = Loader::new(img.0.clone()).unwrap();
                resolvers.push(Some((ctx, is_pie)));
            } else {
                resolvers.push(None);
            }
        }
        Self {
            ranges,
            images,
            resolvers,
        }
    }

    #[must_use]
    pub fn resolve(&self, pc: GuestAddr) -> String {
        let resolve_addr = |addr: GuestAddr| -> String {
            let mut info = String::new();
            if let Some((range, idx)) = self.ranges.get_key_value(&addr) {
                if let Some((ctx, is_pie)) = self.resolvers[*idx].as_ref() {
                    let raddr = if *is_pie { addr - range.start } else { addr };
                    let mut frames = ctx.find_frames(raddr.into()).unwrap().peekable();
                    let mut fname = None;
                    while let Some(frame) = frames.next().unwrap() {
                        // Only use the symbol table if this isn't an inlined function.
                        let symbol = if matches!(frames.peek(), Ok(None)) {
                            ctx.find_symbol(raddr.into())
                        } else {
                            None
                        };
                        if symbol.is_some() {
                            // Prefer the symbol table over the DWARF name because:
                            // - the symbol can include a clone suffix
                            // - llvm may omit the linkage name in the DWARF with -g1
                            fname = Some(print_function(symbol, None));
                        } else if let Some(func) = frame.function {
                            fname = Some(print_function(
                                func.raw_name().ok().as_deref(),
                                func.language,
                            ));
                        } else {
                            fname = Some(print_function(None, None));
                        }
                    }

                    if let Some(name) = fname {
                        info += " in ";
                        info += &name;
                    }

                    if let Some(loc) = ctx.find_location(raddr.into()).unwrap_or(None) {
                        if info.is_empty() {
                            info += " in";
                        }
                        info += " ";
                        if let Some(file) = loc.file {
                            info += file;
                        }
                        if let Some(line) = loc.line {
                            info += ":";
                            info += &line.to_string();
                        }
                    } else {
                        let _ = write!(&mut info, " ({}+{addr:#x})", self.images[*idx].0);
                    }
                }
                if info.is_empty() {
                    let _ = write!(&mut info, " ({}+{addr:#x})", self.images[*idx].0);
                }
            }
            info
        };

        resolve_addr(pc)
    }
}
