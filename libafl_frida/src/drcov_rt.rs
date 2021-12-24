use std::hash::Hasher;
use ahash::AHasher;
use libafl::inputs::{HasTargetBytes, Input};
use libafl_targets::drcov::{DrCovBasicBlock, DrCovWriter};
use libafl::Error;
use rangemap::RangeMap;


pub struct DrCovRuntime {
    pub drcov_basic_blocks: Vec<DrCovBasicBlock>,
    ranges: RangeMap<usize, (u16, String)>,
}

impl DrCovRuntime {
    pub fn new() -> Self {
        Self {
            drcov_basic_blocks: vec![],
            ranges: RangeMap::new(),
        }
    }

    pub fn pre_exec<I: Input + HasTargetBytes>(&mut self, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    pub fn post_exec<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error> {
        let mut hasher = AHasher::new_with_keys(0, 0);
        hasher.write(input.target_bytes().as_slice());

        let filename = format!("./coverage/{:016x}.drcov", hasher.finish(),);
        DrCovWriter::new(&self.ranges).write(&filename, &self.drcov_basic_blocks)?;
        self.drcov_basic_blocks.clear();

        Ok(())
    }


}