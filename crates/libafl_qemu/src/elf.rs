//! Utilities to parse and process ELFs

use std::{fs::File, io::Read, ops::Range, path::Path, str};

use goblin::elf::{Elf, header::ET_DYN};
use libafl::Error;
use libafl_qemu_sys::GuestAddr;

pub struct EasyElf<'a> {
    elf: Elf<'a>,
}

impl<'a> EasyElf<'a> {
    pub fn get_needed(&self) -> Result<Vec<&'a str>, Error> {
        let mut v: Vec<&str> = Vec::new();
        for dyn_lib in &self.elf.libraries {
            v.push(dyn_lib);
        }
        Ok(v)
    }

    pub fn from_file<P>(path: P, buffer: &'a mut Vec<u8>) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let elf = {
            let mut binary_file = File::open(path)?;
            binary_file.read_to_end(buffer)?;
            Elf::parse(buffer).map_err(|e| Error::unknown(format!("{e}")))
        }?;
        Ok(Self { elf })
    }

    pub fn from_slice(buffer: &'a [u8]) -> Result<Self, Error> {
        let elf = Elf::parse(buffer).map_err(|e| Error::unknown(format!("{e}")))?;
        Ok(Self { elf })
    }

    #[must_use]
    pub fn goblin(&self) -> &Elf<'a> {
        &self.elf
    }

    #[must_use]
    pub fn goblin_mut(&mut self) -> &mut Elf<'a> {
        &mut self.elf
    }

    #[must_use]
    pub fn resolve_symbol(&self, name: &str, load_addr: GuestAddr) -> Option<GuestAddr> {
        for sym in &self.elf.syms {
            if let Some(sym_name) = self.elf.strtab.get_at(sym.st_name) {
                if sym_name == name {
                    return if sym.st_value == 0 {
                        None
                    } else if self.is_pic() {
                        #[cfg(cpu_target = "arm")]
                        // Required because of arm interworking addresses aka bit(0) for thumb mode
                        let addr = (sym.st_value as GuestAddr + load_addr) & !(0x1 as GuestAddr);
                        #[cfg(not(cpu_target = "arm"))]
                        let addr = sym.st_value as GuestAddr + load_addr;
                        Some(addr)
                    } else {
                        #[cfg(cpu_target = "arm")]
                        // Required because of arm interworking addresses aka bit(0) for thumb mode
                        let addr = (sym.st_value as GuestAddr) & !(0x1 as GuestAddr);
                        #[cfg(not(cpu_target = "arm"))]
                        let addr = sym.st_value as GuestAddr;
                        Some(addr)
                    };
                }
            }
        }
        None
    }

    #[must_use]
    pub fn get_section(&self, name: &str, load_addr: GuestAddr) -> Option<Range<GuestAddr>> {
        for section in &self.elf.section_headers {
            if let Some(section_name) = self.elf.shdr_strtab.get_at(section.sh_name) {
                log::debug!(
                    "section_name: {section_name:}, sh_addr: 0x{:x}, sh_size: 0x{:x}",
                    section.sh_addr,
                    section.sh_size
                );
                if section_name == name {
                    return if section.sh_addr == 0 {
                        None
                    } else if self.is_pic() {
                        let start = section.sh_addr as GuestAddr + load_addr;
                        let end = start + section.sh_size as GuestAddr;
                        Some(Range { start, end })
                    } else {
                        let start = section.sh_addr as GuestAddr;
                        let end = start + section.sh_size as GuestAddr;
                        Some(Range { start, end })
                    };
                }
            }
        }
        None
    }

    #[must_use]
    pub fn entry_point(&self, load_addr: GuestAddr) -> Option<GuestAddr> {
        if self.elf.entry == 0 {
            None
        } else {
            Some(load_addr + self.elf.entry as GuestAddr)
        }
    }

    #[must_use]
    pub fn is_pic(&self) -> bool {
        self.elf.header.e_type == ET_DYN
    }
}
