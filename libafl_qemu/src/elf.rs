//! Utilities to parse and process ELFs

use goblin::elf::Elf;
use std::{convert::AsRef, fs::File, io::Read, path::Path, str};

use libafl::Error;

pub struct EasyElf<'a> {
    elf: Elf<'a>,
}

impl<'a> EasyElf<'a> {
    pub fn from_file<P>(path: P, buffer: &'a mut Vec<u8>) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let elf = {
            let mut binary_file = File::open(path)?;
            binary_file.read_to_end(buffer)?;
            Elf::parse(buffer).map_err(|e| Error::Unknown(format!("{}", e)))
        }?;
        Ok(Self { elf })
    }

    pub fn from_slice(buffer: &'a [u8]) -> Result<Self, Error> {
        let elf = Elf::parse(buffer).map_err(|e| Error::Unknown(format!("{}", e)))?;
        Ok(Self { elf })
    }

    pub fn goblin(&self) -> &Elf<'a> {
        &self.elf
    }

    pub fn goblin_mut(&mut self) -> &mut Elf<'a> {
        &mut self.elf
    }

    pub fn resolve_symbol(&self, name: &str) -> Option<u64> {
        for sym in self.elf.syms.iter() {
            if let Some(sym_name) = self.elf.strtab.get_at(sym.st_name) {
                if sym_name == name {
                    return if sym.st_value == 0 {
                        None
                    } else {
                        Some(sym.st_value)
                    };
                }
            }
        }
        None
    }
}
