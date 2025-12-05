//! Dump coverage to lcov .info files
//! Use them wit genhtml to generate HTML coverage reports.
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{ffi::c_void, sync::atomic::Ordering};
use std::{collections::HashMap, fs::File, io::Write as IoWrite, path::PathBuf, sync::Mutex};

use libafl::{
    Error,
    corpus::{Corpus, CorpusId},
    stages::ReplayHook,
    state::HasCorpus,
};

use crate::sancov_pcguard::{
    LIBAFL_TARGETS_TRACE_PC_GUARD_HOOK, nop_target_pc_guard, sancov_pcguard_hook_impl,
};

static COVERED_PCS: Mutex<Option<HashMap<usize, usize>>> = Mutex::new(None);

/// A struct containing source location information
#[derive(Debug, Clone)]
pub struct SrcLoc {
    pc: usize,
    function: Option<String>,
    filename: Option<String>,
    line: Option<u32>,
    hits: usize,
}

/// Dump the covered lines
///
/// # Arguments
///
/// * `clear` - Whether to clear the covered lines
///
/// # Returns
///
/// * `Vec<SrcLoc>` - The covered lines, location and symbol
pub fn dump_covered_lines(clear: bool) -> Vec<SrcLoc> {
    let mut res = Vec::new();
    #[allow(clippy::collapsible_if)]
    if let Ok(mut guard) = COVERED_PCS.lock() {
        if let Some(map) = guard.as_mut() {
            for (&pc, &hits) in map.iter() {
                let mut loc = SrcLoc {
                    pc,
                    function: None,
                    filename: None,
                    line: None,
                    hits,
                };

                backtrace::resolve(pc as *mut _, |symbol| {
                    if let Some(name) = symbol.name() {
                        loc.function = Some(name.to_string());
                    }
                    if let Some(filename) = symbol.filename() {
                        loc.filename = Some(filename.display().to_string());
                    }
                    if let Some(lineno) = symbol.lineno() {
                        loc.line = Some(lineno);
                    }
                });
                res.push(loc);
            }
            if clear {
                map.clear();
            }
        }
    }
    res
}

/// Enable coverage collection
pub fn pcguard_enable_coverage_collection() {
    LIBAFL_TARGETS_TRACE_PC_GUARD_HOOK.store(
        __libafl_targets_trace_pc_guard_impl as *mut c_void,
        Ordering::Release,
    );
}

/// Disable coverage collection
pub fn pcguard_disable_coverage_collection() {
    LIBAFL_TARGETS_TRACE_PC_GUARD_HOOK.store(nop_target_pc_guard as *mut c_void, Ordering::Release);
}

/// A hook that dumps coverage to files
#[derive(Debug, Clone)]
pub struct CoverageDumpHook {
    output_dir: Option<PathBuf>,
}

impl CoverageDumpHook {
    /// Create a new [`CoverageDumpHook`]
    ///
    /// Coverage will be dumped to lcov .info files in `output_dir` if provided.
    #[must_use]
    pub fn new(output_dir: Option<PathBuf>) -> Self {
        Self { output_dir }
    }
}

impl<I, S> ReplayHook<I, S> for CoverageDumpHook
where
    S: HasCorpus<I>,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &I, _id: CorpusId) -> Result<(), Error> {
        if self.output_dir.is_some() {
            pcguard_enable_coverage_collection();
        }
        Ok(())
    }

    fn post_exec(&mut self, state: &mut S, _input: &I, id: CorpusId) -> Result<(), Error> {
        if let Some(output_dir) = &self.output_dir {
            let map = dump_covered_lines(true);
            pcguard_disable_coverage_collection();

            let corpus = state.corpus();
            let testcase = corpus.get(id)?.borrow();
            let filename_owned = testcase
                .filename()
                .clone()
                .unwrap_or_else(|| format!("id_{id}"));
            let filename_path = std::path::Path::new(&filename_owned);
            let filename = filename_path
                .file_name()
                .unwrap_or(filename_path.as_os_str());

            let output_path = output_dir.join(format!("{}.info", filename.to_string_lossy()));
            let mut file = File::create(output_path)?;

            let mut lcov_map: HashMap<String, Vec<SrcLoc>> = HashMap::new();
            for loc in map {
                if let Some(filename) = &loc.filename {
                    lcov_map.entry(filename.clone()).or_default().push(loc);
                } else {
                    writeln!(file, "PC: {:x}", loc.pc)?;
                }
            }

            for (filename, locs) in lcov_map {
                writeln!(file, "TN:")?;
                writeln!(file, "SF:{filename}")?;
                for loc in &locs {
                    if let Some(line) = loc.line {
                        if let Some(func) = &loc.function {
                            writeln!(file, "FN:{line},{func}")?;
                            writeln!(file, "FNDA:{},{func}", loc.hits)?;
                        }
                        writeln!(file, "DA:{line},{}", loc.hits)?;
                    }
                }
                writeln!(file, "end_of_record")?;
            }
        }
        Ok(())
    }
}

unsafe extern "C" fn __libafl_targets_trace_pc_guard_impl(guard: *mut u32, pc: usize) {
    unsafe {
        if let Ok(mut guard) = COVERED_PCS.lock() {
            if guard.is_none() {
                *guard = Some(HashMap::new());
            }
            if let Some(map) = guard.as_mut() {
                *map.entry(pc).or_insert(0) += 1;
            }
        }
        sancov_pcguard_hook_impl(guard);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dump_cov() {
        unsafe extern "C" {
            fn __sanitizer_cov_trace_pc_guard(guard: *mut u32);
        }

        pcguard_enable_coverage_collection();

        // Simulate a call to __sanitizer_cov_trace_pc_guard
        let mut guard = 0;
        unsafe {
            __sanitizer_cov_trace_pc_guard(&mut guard);
        }

        let map = dump_covered_lines(true);
        assert!(!map.is_empty());
        for loc in map {
            println!("PC: {:x} -> {:?}", loc.pc, loc.function);
        }
    }
}
