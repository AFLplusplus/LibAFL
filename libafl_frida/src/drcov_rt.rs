//! Generates `DrCov` traces
use ahash::AHasher;
use libafl::{
    inputs::{HasTargetBytes, Input},
    Error,
};
use libafl_targets::drcov::{DrCovBasicBlock, DrCovWriter};
use rangemap::RangeMap;
use std::hash::Hasher;

/// Generates `DrCov` traces
#[derive(Clone, Debug)]
pub struct DrCovRuntime {
    /// The basic blocks of this execution
    pub drcov_basic_blocks: Vec<DrCovBasicBlock>,
    /// The memory ragnes of this target
    ranges: RangeMap<usize, (u16, String)>,
}

impl DrCovRuntime {
    /// Creates a new [`DrCovRuntime`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            drcov_basic_blocks: vec![],
            ranges: RangeMap::new(),
        }
    }

    /// initializes this runtime wiith the given `ranges`
    pub fn init(&mut self, ranges: &RangeMap<usize, (u16, String)>) {
        self.ranges = ranges.clone();
    }

    /// Called before execution, does nothing
    #[allow(clippy::unused_self)]
    pub fn pre_exec<I: Input + HasTargetBytes>(&mut self, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    /// Called after execution, writes the trace to a unique `DrCov` file for this trace
    /// into `./coverage/<trace_hash>.drcov`
    pub fn post_exec<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error> {
        let mut hasher = AHasher::new_with_keys(0, 0);
        hasher.write(input.target_bytes().as_slice());

        let filename = format!("./coverage/{:016x}.drcov", hasher.finish(),);
        DrCovWriter::new(&self.ranges).write(&filename, &self.drcov_basic_blocks)?;
        self.drcov_basic_blocks.clear();

        Ok(())
    }
}

impl Default for DrCovRuntime {
    fn default() -> Self {
        Self::new()
    }
}
