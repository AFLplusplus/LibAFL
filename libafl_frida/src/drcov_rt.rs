//! Generates `DrCov` traces
use crate::helper::FridaRuntime;
use ahash::AHasher;
use libafl::{
    bolts::AsSlice,
    inputs::{HasTargetBytes, Input},
    Error,
};
use libafl_targets::drcov::{DrCovBasicBlock, DrCovWriter};
use rangemap::RangeMap;
use std::collections::HashMap;
use std::hash::Hasher;

/// Generates `DrCov` traces
#[derive(Debug, Clone)]
pub struct DrCovRuntime {
    /// The basic blocks of this execution
    pub drcov_basic_blocks: Vec<DrCovBasicBlock>,
    /// The memory ragnes of this target
    ranges: RangeMap<usize, (u16, String)>,
    stalked_addresses: HashMap<usize, usize>,
}

impl FridaRuntime for DrCovRuntime {
    /// initializes this runtime wiith the given `ranges`
    fn init(
        &mut self,
        _gum: &frida_gum::Gum,
        ranges: &RangeMap<usize, (u16, String)>,
        _modules_to_instrument: &[&str],
    ) {
        self.ranges = ranges.clone();
        std::fs::create_dir_all("./coverage")
            .expect("failed to create directory for coverage files");
    }

    /// Called before execution, does nothing
    fn pre_exec<I: Input + HasTargetBytes>(&mut self, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    /// Called after execution, writes the trace to a unique `DrCov` file for this trace
    /// into `./coverage/<trace_hash>.drcov`
    fn post_exec<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error> {
        let mut hasher = AHasher::new_with_keys(0, 0);
        hasher.write(input.target_bytes().as_slice());

        let filename = format!("./coverage/{:016x}.drcov", hasher.finish(),);
        DrCovWriter::new(&self.ranges).write(&filename, &self.drcov_basic_blocks)?;
        self.drcov_basic_blocks.clear();

        Ok(())
    }
}

impl DrCovRuntime {
    /// Creates a new [`DrCovRuntime`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            drcov_basic_blocks: vec![],
            ranges: RangeMap::new(),
            stalked_addresses: HashMap::new(),
        }
    }

    /// Add a stalked address to real address mapping.
    #[inline]
    pub fn add_stalked_address(&mut self, stalked: usize, real: usize) {
        self.stalked_addresses.insert(stalked, real);
    }

    /// Resolves the real address from a stalker stalked address if possible, if there is no
    /// real address, the stalked address is returned.
    #[must_use]
    pub fn real_address_for_stalked(&self, stalked: usize) -> usize {
        self.stalked_addresses
            .get(&stalked)
            .map_or(stalked, |addr| *addr)
    }
}

impl Default for DrCovRuntime {
    fn default() -> Self {
        Self::new()
    }
}
