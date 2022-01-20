//! [`DrCov`](https://dynamorio.org/page_drcov.html) support for `LibAFL` frida mode,
//! writing basic-block trace files to be read by coverage analysis tools, such as [Lighthouse](https://github.com/gaasedelen/lighthouse),
//! [bncov](https://github.com/ForAllSecure/bncov), [dragondance](https://github.com/0ffffffffh/dragondance), etc.

use core::ptr::addr_of;
use libafl::Error;
use rangemap::RangeMap;
use std::{
    fs::File,
    io::{BufWriter, Write},
    path::Path,
};

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
    pub fn new_with_size(start: usize, size: usize) -> Self {
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
                    std::slice::from_raw_parts(addr_of!(basic_block) as *const u8, 8)
                })
                .unwrap();
        }

        writer.flush()?;
        Ok(())
    }
}
