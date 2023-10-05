//! Generates `DrCov` traces
use std::{
    hash::{BuildHasher, Hasher},
    path::{Path, PathBuf},
    rc::Rc,
};

use ahash::RandomState;
use frida_gum::ModuleMap;
use libafl::{
    inputs::{HasTargetBytes, Input},
    Error,
};
use libafl_bolts::AsSlice;
use libafl_targets::drcov::{DrCovBasicBlock, DrCovWriter};
use rangemap::RangeMap;

use crate::helper::FridaRuntime;

/// Generates `DrCov` traces
#[derive(Debug, Clone)]
pub struct DrCovRuntime {
    /// The basic blocks of this execution
    pub drcov_basic_blocks: Vec<DrCovBasicBlock>,
    /// The memory ragnes of this target
    ranges: RangeMap<usize, (u16, String)>,
    coverage_directory: PathBuf,
}

impl FridaRuntime for DrCovRuntime {
    /// initializes this runtime wiith the given `ranges`
    fn init(
        &mut self,
        _gum: &frida_gum::Gum,
        ranges: &RangeMap<usize, (u16, String)>,
        _module_map: &Rc<ModuleMap>,
    ) {
        self.ranges = ranges.clone();
        std::fs::create_dir_all(&self.coverage_directory)
            .expect("failed to create directory for coverage files");
    }

    /// Called before execution, does nothing
    fn pre_exec<I: Input + HasTargetBytes>(&mut self, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    /// Called after execution, writes the trace to a unique `DrCov` file for this trace
    /// into `./coverage/<trace_hash>.drcov`
    fn post_exec<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error> {
        let mut hasher = RandomState::with_seeds(0, 0, 0, 0).build_hasher();
        hasher.write(input.target_bytes().as_slice());

        let filename = self
            .coverage_directory
            .join(format!("{:016x}.drcov", hasher.finish(),));
        DrCovWriter::new(&self.ranges).write(filename, &self.drcov_basic_blocks)?;
        self.drcov_basic_blocks.clear();

        Ok(())
    }
}

impl DrCovRuntime {
    /// Creates a new [`DrCovRuntime`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new [`DrCovRuntime`] that writes coverage to the specified directory
    pub fn with_path<P: AsRef<Path>>(path: P) -> Self {
        Self {
            coverage_directory: path.as_ref().into(),
            ..Self::default()
        }
    }
}

impl Default for DrCovRuntime {
    fn default() -> Self {
        Self {
            drcov_basic_blocks: vec![],
            ranges: RangeMap::new(),
            coverage_directory: PathBuf::from("./coverage"),
        }
    }
}
