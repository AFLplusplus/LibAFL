//! [`DrCov`](https://dynamorio.org/page_drcov.html) support for `LibAFL` `FRIDA` mode.
//!
//! It's writing basic-block trace files to be read by coverage analysis tools, such as [Lighthouse](https://github.com/gaasedelen/lighthouse),
//! [bncov](https://github.com/ForAllSecure/bncov), [cartographer](https://github.com/nccgroup/Cartographer), etc.

use alloc::{string::String, vec::Vec};
use core::{fmt::Debug, num::ParseIntError, ptr};
use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use hashbrown::HashSet;
use libafl::Error;
use rangemap::RangeMap;

/// A basic block struct
/// This can be used to keep track of new addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrCovBasicBlock {
    /// Start of this basic block
    pub start: u64,
    /// End of this basic block
    pub end: u64,
}

/// A (Raw) Basic Block List Entry.
/// This is only relevant in combination with a [`DrCovReader`] or a [`DrCovWriter`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct DrCovBasicBlockEntry {
    /// Start of this basic block
    pub start: u32,
    /// Size of this basic block
    size: u16,
    /// The id of the `DrCov` module this block is in
    mod_id: u16,
}

impl From<&[u8; 8]> for DrCovBasicBlockEntry {
    fn from(value: &[u8; 8]) -> Self {
        // # Safety
        // The value is a valid u8 pointer.
        // There's a chance that the value is not aligned to 32 bit, so we use `read_unaligned`.
        assert_eq!(
            size_of::<DrCovBasicBlockEntry>(),
            size_of::<[u8; 8]>(),
            "`DrCovBasicBlockEntry` size changed!"
        );
        unsafe { ptr::read_unaligned(ptr::from_ref(value) as *const DrCovBasicBlockEntry) }
    }
}

impl From<DrCovBasicBlockEntry> for [u8; 8] {
    fn from(value: DrCovBasicBlockEntry) -> Self {
        // # Safety
        // The value is a c struct.
        // Casting its pointer to bytes should be safe.
        // The resulting pointer needs to be less aligned.
        assert_eq!(
            size_of::<DrCovBasicBlockEntry>(),
            size_of::<[u8; 8]>(),
            "`DrCovBasicBlockEntry` size changed!"
        );
        unsafe { core::slice::from_raw_parts(ptr::from_ref(&value).cast::<u8>(), 8) }
            .try_into()
            .unwrap()
    }
}

impl From<&DrCovBasicBlockEntry> for &[u8] {
    fn from(value: &DrCovBasicBlockEntry) -> Self {
        // # Safety
        // The value is a c struct.
        // Casting its pointer to bytes should be safe.
        unsafe {
            core::slice::from_raw_parts(
                ptr::from_ref(value).cast::<u8>(),
                size_of::<DrCovBasicBlockEntry>(),
            )
        }
    }
}

/// A writer for `DrCov` files
#[derive(Debug)]
pub struct DrCovWriter<'a> {
    module_mapping: &'a RangeMap<u64, (u16, String)>,
}

impl DrCovBasicBlock {
    /// Create a new [`DrCovBasicBlock`] with the given `start` and `end` addresses.
    #[must_use]
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// Create a new [`DrCovBasicBlock`] with a given `start` address and a block size.
    #[must_use]
    pub fn with_size(start: u64, size: usize) -> Self {
        Self::new(start, start + u64::try_from(size).unwrap())
    }
}

impl<'a> DrCovWriter<'a> {
    /// Create a new [`DrCovWriter`]
    #[must_use]
    pub fn new(module_mapping: &'a RangeMap<u64, (u16, String)>) -> Self {
        Self { module_mapping }
    }

    /// Write the list of basic blocks to a `DrCov` file.
    pub fn write<P>(&mut self, path: P, basic_blocks: &[DrCovBasicBlock]) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        let mut writer = BufWriter::new(File::create(path)?);
        let modules = self.module_entries();

        writer.write_all(b"DRCOV VERSION: 2\nDRCOV FLAVOR: libafl\n")?;
        writer
            .write_all(format!("Module Table: version 2, count {}\n", modules.len()).as_bytes())?;
        writer.write_all(b"Columns: id, base, end, entry, checksum, timestamp, path\n")?;
        for module in modules {
            writer.write_all(module.to_module_line().as_bytes())?;
            writer.write_all(b"\n")?;
        }

        writer.write_all(format!("BB Table: {} bbs\n", basic_blocks.len()).as_bytes())?;
        for block in self.basic_block_entries(basic_blocks) {
            writer.write_all((&block).into()).unwrap();
        }

        writer.flush()?;
        Ok(())
    }

    /// Gets a [`Vec`] of all [`DrCovModuleEntry`] elements in this [`DrCovWriter`].
    #[must_use]
    pub fn module_entries(&self) -> Vec<DrCovModuleEntry> {
        self.module_mapping
            .iter()
            .map(|x| {
                let (range, (id, path)) = x;
                DrCovModuleEntry {
                    id: *id,
                    base: range.start,
                    end: range.end,
                    entry: 0,
                    checksum: 0,
                    timestamp: 0,
                    path: PathBuf::from(path),
                }
            })
            .collect()
    }

    /// Gets a [`Vec`] of all [`DrCovBasicBlockEntry`] elements from a list of [`DrCovBasicBlock`] entries using the modules from this [`DrCovWriter`].
    #[must_use]
    pub fn basic_block_entries(
        &self,
        basic_blocks: &[DrCovBasicBlock],
    ) -> Vec<DrCovBasicBlockEntry> {
        let mut ret = Vec::with_capacity(basic_blocks.len());
        for block in basic_blocks {
            let (range, (id, _)) = self
                .module_mapping
                .get_key_value(&block.start)
                .unwrap_or_else(|| {
                    panic!(
                        "Could not read module at addr {:?}. Module list: {:?}.",
                        block.start, self.module_mapping
                    )
                });
            let basic_block = DrCovBasicBlockEntry {
                start: (block.start - range.start) as u32,
                size: (block.end - block.start) as u16,
                mod_id: *id,
            };
            ret.push(basic_block);
        }
        ret
    }

    /// Creates a [`DrCovReader`] module out of this [`DrCovWriter`]
    #[must_use]
    pub fn to_reader(&self, basic_blocks: &[DrCovBasicBlock]) -> DrCovReader {
        let modules = self.module_entries();
        let basic_blocks = self.basic_block_entries(basic_blocks);

        DrCovReader::from_data(modules, basic_blocks)
    }
}

/// An entry in the `DrCov` module list.
#[derive(Debug, Clone)]
pub struct DrCovModuleEntry {
    /// The index of this module
    pub id: u16,
    /// Base of this module
    pub base: u64,
    /// End address of this module
    pub end: u64,
    /// Entry (can be zero)
    pub entry: usize,
    /// Checksum (can be zero)
    pub checksum: usize,
    /// Timestamp (can be zero)
    pub timestamp: usize,
    /// The path of this module
    pub path: PathBuf,
}

impl DrCovModuleEntry {
    /// Gets the module line from this [`DrCovModuleEntry`]
    #[must_use]
    pub fn to_module_line(&self) -> String {
        format!(
            "{:03}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, {:?}",
            self.id, self.base, self.end, self.entry, self.checksum, self.timestamp, self.path
        )
    }
}

/// Read `DrCov` (v2) files created with [`DrCovWriter`] or other tools
pub struct DrCovReader {
    /// The modules in this `DrCov` file
    pub module_entries: Vec<DrCovModuleEntry>,
    /// The list of basic blocks as [`DrCovBasicBlockEntry`].
    /// To get the blocks as [`DrCovBasicBlock`], call [`Self::basic_blocks`] instead.
    pub basic_block_entries: Vec<DrCovBasicBlockEntry>,
}

impl Debug for DrCovReader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DrCovReader")
            .field("modules", &self.module_entries)
            .field("basic_blocks", &self.basic_block_entries.len())
            .finish()
    }
}

fn parse_hex_to_usize(str: &str) -> Result<usize, ParseIntError> {
    // Cut off the first 0x
    usize::from_str_radix(&str[2..], 16)
}

fn parse_hex_to_u64(str: &str) -> Result<u64, ParseIntError> {
    // Cut off the first 0x
    u64::from_str_radix(&str[2..], 16)
}

fn parse_path(s: &str) -> PathBuf {
    let s = s.trim();

    // If first and last character is a quote, let's remove them
    let s = if s.starts_with('\"') && s.ends_with('\"') {
        &s[1..s.len() - 1]
    } else {
        s
    };

    PathBuf::from(s)
}

impl DrCovReader {
    /// Parse a `drcov` file to memory.
    pub fn read<P: AsRef<Path> + ?Sized>(file: &P) -> Result<Self, Error> {
        let f = File::open(file)?;
        let mut reader = BufReader::new(f);

        let mut header = String::new();
        reader.read_line(&mut header)?;

        let drcov_version = "DRCOV VERSION: 2";
        if header.to_uppercase().trim() != drcov_version {
            return Err(Error::illegal_state(format!(
                "No valid header. Expected {drcov_version} but got {header}"
            )));
        }

        header.clear();
        reader.read_line(&mut header)?;

        let drcov_flavor = "DRCOV FLAVOR:";
        if header.to_uppercase().starts_with(drcov_flavor) {
            // Ignore flavor line if it's not present.
            log::info!("Got drcov flavor {drcov_flavor}");

            header.clear();
            reader.read_line(&mut header)?;
        }

        let Some(Ok(module_count)) = header
            .split("Module Table: version 2, count ")
            .nth(1)
            .map(|x| x.trim().parse::<usize>())
        else {
            return Err(Error::illegal_state(format!(
                "Expected module table but got: {header}"
            )));
        };

        header.clear();
        reader.read_line(&mut header)?;

        if !header.starts_with("Columns: id, base, end, entry, checksum, timestamp, path") {
            return Err(Error::illegal_state(format!(
                "Module table has unknown or illegal columns: {header}"
            )));
        }

        let mut modules = Vec::with_capacity(module_count);

        for _ in 0..module_count {
            header.clear();
            reader.read_line(&mut header)?;

            let err = |x| {
                Error::illegal_argument(format!(
                    "Unexpected module entry while parsing {x} in header: {header}"
                ))
            };

            let mut split = header.split(", ");

            let Some(Ok(id)) = split.next().map(str::parse) else {
                return Err(err("id"));
            };

            let Some(Ok(base)) = split.next().map(parse_hex_to_u64) else {
                return Err(err("base"));
            };

            let Some(Ok(end)) = split.next().map(parse_hex_to_u64) else {
                return Err(err("end"));
            };

            let Some(Ok(entry)) = split.next().map(parse_hex_to_usize) else {
                return Err(err("entry"));
            };

            let Some(Ok(checksum)) = split.next().map(parse_hex_to_usize) else {
                return Err(err("checksum"));
            };

            let Some(Ok(timestamp)) = split.next().map(parse_hex_to_usize) else {
                return Err(err("timestamp"));
            };

            let Some(path) = split.next().map(parse_path) else {
                return Err(err("path"));
            };

            modules.push(DrCovModuleEntry {
                id,
                base,
                end,
                entry,
                checksum,
                timestamp,
                path,
            });
        }

        header.clear();
        reader.read_line(&mut header)?;

        //"BB Table: {} bbs\n"
        if !header.starts_with("BB Table: ") {
            return Err(Error::illegal_state(format!(
                "Error reading BB Table header. Got: {header}"
            )));
        }
        let mut bb = header.split(' ');
        let Some(Ok(bb_count)) = bb.nth(2).map(str::parse) else {
            return Err(Error::illegal_state(format!(
                "Error parsing BB Table header count. Got: {header}"
            )));
        };

        let mut basic_blocks = Vec::with_capacity(bb_count);

        for _ in 0..bb_count {
            let mut bb_entry = [0_u8; 8];
            reader.read_exact(&mut bb_entry)?;
            basic_blocks.push((&bb_entry).into());
        }

        Ok(DrCovReader {
            module_entries: modules,
            basic_block_entries: basic_blocks,
        })
    }

    /// Creates a [`DrCovReader`] pre-filled with data.
    /// Rather pointless, use [`Self::read`] to actually read a file from disk.
    #[must_use]
    pub fn from_data(
        modules: Vec<DrCovModuleEntry>,
        basic_blocks: Vec<DrCovBasicBlockEntry>,
    ) -> Self {
        Self {
            module_entries: modules,
            basic_block_entries: basic_blocks,
        }
    }

    /// Get a list of traversed [`DrCovBasicBlock`] nodes
    #[must_use]
    pub fn basic_blocks(&self) -> Vec<DrCovBasicBlock> {
        let mut ret = Vec::with_capacity(self.basic_block_entries.len());

        for basic_block in &self.basic_block_entries {
            let bb_id = basic_block.mod_id;
            if let Some(module) = self.module_by_id(bb_id) {
                let start = module.base + u64::from(basic_block.start);
                let end = start + u64::from(basic_block.size);
                ret.push(DrCovBasicBlock::new(start, end));
            } else {
                log::error!("Skipping basic block outside of any modules: {basic_block:?}");
            }
        }
        ret
    }

    /// Get the module (range) map. This can be used to create a new [`DrCovWriter`].
    #[must_use]
    pub fn module_map(&self) -> RangeMap<u64, (u16, String)> {
        let mut ret = RangeMap::new();
        for module in &self.module_entries {
            ret.insert(
                module.base..module.end,
                (
                    module.id,
                    module.path.clone().into_os_string().into_string().unwrap(),
                ),
            );
        }
        ret
    }

    /// Writes this data out to disk (again).
    pub fn write<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let ranges = self.module_map();
        let mut writer = DrCovWriter::new(&ranges);
        writer.write(path, &self.basic_blocks())
    }

    /// Gets a list of all basic blocks, as absolute addresses, for u64 targets.
    /// Useful for example for [`JmpScare`](https://github.com/fgsect/JMPscare) and other analyses.
    #[must_use]
    pub fn basic_block_addresses_u64(&self) -> Vec<u64> {
        self.basic_blocks().iter().map(|x| x.start).collect()
    }

    /// Gets a list of all basic blocks, as absolute addresses, for u32 targets.
    /// Will return an [`Error`] if addresses are larger than 32 bit.
    pub fn basic_block_addresses_u32(&self) -> Result<Vec<u32>, Error> {
        let blocks = self.basic_blocks();
        let mut ret = Vec::with_capacity(blocks.len());
        for block in self.basic_blocks() {
            ret.push(u32::try_from(block.start)?);
        }
        Ok(ret)
    }

    /// Merges the contents of another [`DrCovReader`] instance into this one.
    /// Useful to merge multiple coverage files of a fuzzing run into one drcov file.
    /// Similar to [drcov-merge](https://github.com/vanhauser-thc/drcov-merge).
    ///
    /// If `unique` is set to 1, each block will end up in the resulting [`DrCovReader`] at most once.
    ///
    /// Will return an `Error` if the individual modules are not mergable.
    /// In this case, the module list may already have been changed.
    pub fn merge(&mut self, other: &DrCovReader, unique: bool) -> Result<(), Error> {
        for module in &other.module_entries {
            if let Some(own_module) = self.module_by_id(module.id) {
                // Module exists, make sure it's the same.
                if own_module.base != module.base || own_module.end != module.end {
                    return Err(Error::illegal_argument(format!(
                        "Module id of file to merge doesn't fit! Own modules: {:#x?}, other modules: {:#x?}",
                        self.module_entries, other.module_entries
                    )));
                }
            } else {
                // We don't know the module. Insert as new module.
                self.module_entries.push(module.clone());
            }
        }

        if unique {
            self.make_unique();
        }
        let mut blocks = HashSet::new();

        for block in &self.basic_block_entries {
            blocks.insert(*block);
        }

        for block in &other.basic_block_entries {
            if !blocks.contains(block) {
                blocks.insert(*block);
                self.basic_block_entries.push(*block);
            }
        }

        Ok(())
    }

    /// Remove blocks that exist more than once in the trace, in-place.
    pub fn make_unique(&mut self) {
        let mut blocks = HashSet::new();
        let new_vec = self
            .basic_block_entries
            .iter()
            .filter(|x| {
                if blocks.contains(x) {
                    false
                } else {
                    blocks.insert(*x);
                    true
                }
            })
            .copied()
            .collect();
        drop(blocks);

        self.basic_block_entries = new_vec;
    }

    /// Returns the module for a given `id`, or [`None`].
    #[must_use]
    pub fn module_by_id(&self, id: u16) -> Option<&DrCovModuleEntry> {
        self.module_entries.iter().find(|module| module.id == id)
    }
}

#[cfg(test)]
mod test {
    use alloc::string::{String, ToString};
    use std::{env::temp_dir, fs, path::PathBuf};

    use rangemap::RangeMap;

    use super::{DrCovModuleEntry, DrCovReader, DrCovWriter};
    use crate::drcov::{DrCovBasicBlock, DrCovBasicBlockEntry};

    #[test]
    fn test_write_read_drcov() {
        let mut ranges = RangeMap::<u64, (u16, String)>::new();

        ranges.insert(0x00..0x4242, (0xffff, "fuzzer".to_string()));

        ranges.insert(0x4242..0xFFFF, (0, "Entry0".to_string()));
        ranges.insert(0xFFFF..0x424242, (1, "Entry1".to_string()));

        let mut writer = DrCovWriter::new(&ranges);

        let tmpdir = temp_dir();

        let drcov_tmp_file = tmpdir.join("drcov_test.drcov");
        writer
            .write(
                &drcov_tmp_file,
                &[
                    DrCovBasicBlock::new(0x4242, 0x4250),
                    DrCovBasicBlock::new(0x10, 0x100),
                    DrCovBasicBlock::new(0x424200, 0x424240),
                    DrCovBasicBlock::new(0x10, 0x100),
                ],
            )
            .unwrap();

        let reader = DrCovReader::read(&drcov_tmp_file).unwrap();

        assert_eq!(reader.basic_block_entries.len(), 4);
        assert_eq!(reader.module_map().len(), 3);
        assert_eq!(reader.basic_blocks().len(), 4);

        // Let's do one more round :)
        reader.write(&drcov_tmp_file).unwrap();
        let reader = DrCovReader::read(&drcov_tmp_file).unwrap();

        assert_eq!(reader.basic_block_entries.len(), 4);
        assert_eq!(reader.module_map().len(), 3);
        assert_eq!(reader.basic_blocks().len(), 4);

        fs::remove_file(&drcov_tmp_file).unwrap();
    }

    #[test]
    fn test_merge() {
        let modules = vec![DrCovModuleEntry {
            id: 0,
            base: 0,
            end: 0x4242,
            entry: 0,
            checksum: 0,
            timestamp: 0,
            path: PathBuf::new(),
        }];
        let basic_blocks1 = vec![DrCovBasicBlockEntry {
            mod_id: 0,
            start: 0,
            size: 42,
        }];

        let mut basic_blocks2 = basic_blocks1.clone();
        basic_blocks2.push(DrCovBasicBlockEntry {
            mod_id: 0,
            start: 4200,
            size: 42,
        });

        let mut first = DrCovReader::from_data(modules.clone(), basic_blocks1);
        let second = DrCovReader::from_data(modules, basic_blocks2);

        first.merge(&second, true).unwrap();
        assert_eq!(first.basic_block_entries.len(), 2);
    }
}
