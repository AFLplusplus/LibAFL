//! [`DrCov`](https://dynamorio.org/page_drcov.html) support for `LibAFL` frida mode,
//! writing basic-block trace files to be read by coverage analysis tools, such as [Lighthouse](https://github.com/gaasedelen/lighthouse),
//! [bncov](https://github.com/ForAllSecure/bncov), [dragondance](https://github.com/0ffffffffh/dragondance), etc.

use rangemap::RangeMap;
use std::{
    fs::File,
    io::{BufWriter, Write},
};

/// A basic block struct
#[derive(Clone, Copy)]
pub struct DrCovBasicBlock {
    start: usize,
    end: usize,
}

/// A writer for `DrCov` files
pub struct DrCovWriter<'a> {
    writer: BufWriter<File>,
    module_mapping: &'a RangeMap<usize, (u16, String)>,
    basic_blocks: &'a mut Vec<DrCovBasicBlock>,
}

#[repr(C)]
struct DrCovBasicBlockEntry {
    start: u32,
    size: u16,
    mod_id: u16,
}

impl DrCovBasicBlock {
    /// Create a new [`DrCovBasicBlock`] with the given `start` and `end` addresses.
    #[must_use]
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}
impl<'a> DrCovWriter<'a> {
    /// Create a new [`DrCovWriter`]
    pub fn new(
        path: &str,
        module_mapping: &'a RangeMap<usize, (u16, String)>,
        basic_blocks: &'a mut Vec<DrCovBasicBlock>,
    ) -> Self {
        Self {
            writer: BufWriter::new(
                File::create(path).expect("unable to create file for coverage data"),
            ),
            module_mapping,
            basic_blocks,
        }
    }

    /// Write the `DrCov` file.
    pub fn write(&mut self) {
        self.writer
            .write_all(b"DRCOV VERSION: 2\nDRCOV FLAVOR: libafl\n")
            .unwrap();

        let modules: Vec<(&std::ops::Range<usize>, &(u16, String))> =
            self.module_mapping.iter().collect();
        self.writer
            .write_all(format!("Module Table: version 2, count {}\n", modules.len()).as_bytes())
            .unwrap();
        self.writer
            .write_all(b"Columns: id, base, end, entry, checksum, timestamp, path\n")
            .unwrap();
        for module in modules {
            let (range, (id, path)) = module;
            self.writer
                .write_all(
                    format!(
                        "{:03}, 0x{:x}, 0x{:x}, 0x00000000, 0x00000000, 0x00000000, {}\n",
                        id, range.start, range.end, path
                    )
                    .as_bytes(),
                )
                .unwrap();
        }
        self.writer
            .write_all(format!("BB Table: {} bbs\n", self.basic_blocks.len()).as_bytes())
            .unwrap();
        for block in self.basic_blocks.drain(0..) {
            let (range, (id, _)) = self.module_mapping.get_key_value(&block.start).unwrap();
            let basic_block = DrCovBasicBlockEntry {
                start: (block.start - range.start) as u32,
                size: (block.end - block.start) as u16,
                mod_id: *id,
            };
            self.writer
                .write_all(unsafe {
                    std::slice::from_raw_parts(&basic_block as *const _ as *const u8, 8)
                })
                .unwrap();
        }

        self.writer.flush().unwrap();
    }
}
