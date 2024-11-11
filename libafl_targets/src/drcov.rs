//! [`DrCov`](https://dynamorio.org/page_drcov.html) support for `LibAFL` `FRIDA` mode.
//!
//! It's writing basic-block trace files to be read by coverage analysis tools, such as [Lighthouse](https://github.com/gaasedelen/lighthouse),
//! [bncov](https://github.com/ForAllSecure/bncov), [dragondance](https://github.com/0ffffffffh/dragondance), etc.

use alloc::{string::String, vec::Vec};
use core::ptr;
use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use libafl::Error;
use rangemap::RangeMap;

/// A basic block struct
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrCovBasicBlock {
    /// Start of this basic block
    pub start: usize,
    /// End of this basic block
    pub end: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
struct DrCovBasicBlockEntry {
    start: u32,
    size: u16,
    mod_id: u16,
}

impl From<&[u8; 8]> for DrCovBasicBlockEntry {
    fn from(value: &[u8; 8]) -> Self {
        // # Safety
        // The value is a valid u8 pointer.
        // There's a chance that the value is not aligned to 32 bit, so we use `read_unaligned`.
        unsafe {
            ptr::read_unaligned(value as *const u8 as *const DrCovBasicBlockEntry)
        }
    }
}

/// A writer for `DrCov` files
#[derive(Debug)]
pub struct DrCovWriter<'a> {
    module_mapping: &'a RangeMap<usize, (u16, String)>,
}

impl DrCovBasicBlock {
    /// Create a new [`DrCovBasicBlock`] with the given `start` and `end` addresses.
    #[must_use]
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// Create a new [`DrCovBasicBlock`] with a given `start` address and a block size.
    #[must_use]
    pub fn with_size(start: usize, size: usize) -> Self {
        Self::new(start, start + size)
    }
}

impl<'a> DrCovWriter<'a> {
    /// Create a new [`DrCovWriter`]
    #[must_use]
    pub fn new(module_mapping: &'a RangeMap<usize, (u16, String)>) -> Self {
        Self { module_mapping }
    }

    /// Write the list of basic blocks to a `DrCov` file.
    pub fn write<P>(&mut self, path: P, basic_blocks: &[DrCovBasicBlock]) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        let mut writer = BufWriter::new(File::create(path)?);

        writer
            .write_all(b"DRCOV VERSION: 2\nDRCOV FLAVOR: libafl\n")
            .unwrap();

        let modules: Vec<(&std::ops::Range<usize>, &(u16, String))> =
            self.module_mapping.iter().collect();
        writer
            .write_all(format!("Module Table: version 2, count {}\n", modules.len()).as_bytes())
            .unwrap();
        writer
            .write_all(b"Columns: id, base, end, entry, checksum, timestamp, path\n")
            .unwrap();
        for module in modules {
            let (range, (id, path)) = module;
            writer
                .write_all(
                    format!(
                        "{:03}, 0x{:x}, 0x{:x}, 0x00000000, 0x00000000, 0x00000000, {}\n",
                        id, range.start, range.end, path
                    )
                    .as_bytes(),
                )
                .unwrap();
        }
        writer
            .write_all(format!("BB Table: {} bbs\n", basic_blocks.len()).as_bytes())
            .unwrap();
        for block in basic_blocks {
            let (range, (id, _)) = self.module_mapping.get_key_value(&block.start).unwrap();
            let basic_block = DrCovBasicBlockEntry {
                start: (block.start - range.start) as u32,
                size: (block.end - block.start) as u16,
                mod_id: *id,
            };
            writer
                .write_all(unsafe {
                    std::slice::from_raw_parts(&raw const (basic_block) as *const u8, 8)
                })
                .unwrap();
        }

        writer.flush()?;
        Ok(())
    }
}

/// An entry in the `DrCov` module list.
#[derive(Debug)]
pub struct DrCovModuleEntry {
    /// The index of this module
    pub id: u16,
    /// Base of this module
    pub base: usize,
    /// End address of this module
    pub end: usize,
    /// Entry (can be zero)
    pub entry: usize,
    /// Checksum (can be 0)
    pub checksum: usize,
    /// Timestamp (can be 0)
    pub timestamp: usize,
    /// The path of this module
    pub path: PathBuf,
}

/// Read `DrCov` (v2) files created with [`DrCovWriter`] or other tools
#[derive(Debug)]
pub struct DrCovReader {
    pub module_mapping: RangeMap<usize, (u16, String)>,   
    pub modules: Vec<DrCovModuleEntry>,
    pub basic_blocks: Vec<DrCovBasicBlockEntry>,
}

impl DrCovReader {
    fn from_file<P: AsRef<Path> + ?Sized>(file: &P) -> Result<Self, Error> {
        let f = File::open(file)?;
        let mut reader = BufReader::new(f);

        let mut header = String::new();
        reader.read_line(&mut header)?;

        let drcov_version = "DRCOV VERSION: 2";
        if header.to_uppercase() != drcov_version {
            return Err(Error::illegal_state(format!("No valid header. Expected {drcov_version} but got {header}")));
        }

        reader.read_line(&mut header)?;

        let drcov_flavor = "DRCOV_FLAVOR:";
        if header.to_uppercase().starts_with(drcov_flavor) {
            // Ignore flavor line if it's not present.
            log::info!("Got drcov flavor {drcov_flavor}");

            reader.read_line(&mut header)?;

        }

        let Some(module_count) = header.split("Module Table: version 2, count ").skip(1).next().map(|x| x.parse::<usize>()) else {
            return Err(Error::illegal_state(format!("Expected module table but got: {header}")));
        };
        let module_count = module_count?;

        reader.read_line(&mut header)?;

        if !header.starts_with("Columns: id, base, end, entry, checksum, timestamp, path") {
            return Err(Error::illegal_state(format!("Module table has unknown or illegal columns: {header}")));
        }

        let mut modules = Vec::with_capacity(module_count);

        for _ in 0..module_count {
            reader.read_line(&mut header)?;

            let err= |x| Error::illegal_argument(format!("Unexpected module entry while parsing {x} in header: {header}"));

            let mut split = header.split(", ");

            let Some(id) = split.next().map(|x| x.parse::<u16>()) else {
                return Err(err("id"))
            };
            let id = id?;

            let Some(base) = split.next().map(|s| s.parse::<usize>()) else {
                return Err(err("base"));
            };
            let base = base?;

            let Some(end) = split.next().map(|s| s.parse::<usize>()) else {
                return Err(err("end"));
            };
            let end = end?;

            let Some(entry) = split.next().map(|s| s.parse::<usize>()) else {
                return Err(err("entry"))
            };
            let entry = entry?;

            let Some(checksum) = split.next().map(|s| s.parse::<usize>()) else {
                return Err(err("checksum"));
            };
            let checksum = checksum?;

            let Some(timestamp) = split.next().map(|s| s.parse::<usize>()) else {
                return Err(err("timestamp"));
            };
            let timestamp = timestamp?;

            let Some(path) = split.next().map(|s| PathBuf::from(s.trim())) else {
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
            })

        }

        reader.read_line(&mut header)?;

        //"BB Table: {} bbs\n"
        if !header.starts_with("BB Table: ") {
            return Err(Error::illegal_state("Error reading BB Table header. Got: {header}"));
        }
        let bb = header.split(" ");
        let Some(Ok(bb_count)) = bb.skip(1).next().map(|x| x.parse::<usize>()) else {
            return Err(Error::illegal_state("Error parsing BB Table header count. Got: {header}"));
        };

        let mut basic_blocks = Vec::with_capacity(bb_count);

        for _ in 0..bb_count {
            let mut bb_entry = [0_u8; 8];
            reader.read_exact(&mut bb_entry)?;
            basic_blocks.push((&bb_entry).into());
        }

        Ok(DrCovReader {
            module_mapping: RangeMap::new(),
            modules,
            basic_blocks,
        })
    }
}

#[cfg(test)]
mod test {
    use std::{fs, string::{String, ToString}};

    use rangemap::RangeMap;

    use super::{DrCovReader, DrCovWriter};

    #[test]
    fn test_write_read_drcov() {

        let mut ranges = RangeMap::<usize, (u16, String)>::new();

        ranges.insert(
            0x00..0x4242,
            (0xffff, "fuzzer".to_string()),
        );

        ranges.insert(0x4242..0xFFFF, (0, "Entry0".to_string()));
        ranges.insert(0xFFFF..0x424242, (1, "Entry1".to_string()));

        let mut writer = DrCovWriter::new(&ranges);

        let drcov_tmp_file = "drcov_test.drcov";
        writer.write(drcov_tmp_file, &[]).unwrap();

        let reader = DrCovReader::from_file(drcov_tmp_file).unwrap();

        fs::remove_file("drcov_test.drcov").unwrap();
        panic!("Reader: {reader:?}");

    }
}
