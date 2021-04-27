use std::{
    fs::File,
    io::{BufWriter, Write},
};
use rangemap::RangeMap;

pub struct DrCovWriter<'a> {
    writer: BufWriter<File>,
    module_mapping: &'a RangeMap<usize, (u16, &'a str)>,
    basic_blocks: &'a mut Vec<(usize, usize)>,
}

#[repr(C)]
struct DrCovBasicBlockEntry {
    start: u32,
    size: u16,
    mod_id: u16,
}

impl<'a> DrCovWriter<'a> {
    pub fn new(
        path: &str,
        module_mapping: &'a RangeMap<usize, (u16, &str)>,
        basic_blocks: &'a mut Vec<(usize, usize)>,
    ) -> Self {
        Self {
            writer: BufWriter::new(
                File::create(path).expect("unable to create file for coverage data"),
            ),
            module_mapping,
            basic_blocks,
        }
    }

    pub fn write(&mut self) {
        self.writer
            .write_all(b"DRCOV VERSION: 2\nDRCOV FLAVOR: libafl\n")
            .unwrap();

        let modules: Vec<(&std::ops::Range<usize>, &(u16, &str))> =
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
        for (start, end) in self.basic_blocks.drain(0..) {
            let (range, (id, _)) = self.module_mapping.get_key_value(&start).unwrap();
            let basic_block = DrCovBasicBlockEntry {
                start: (start - range.start) as u32,
                size: (end - start) as u16,
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

