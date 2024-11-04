use std::{collections::VecDeque, path::PathBuf};

use hashbrown::HashSet;
use libafl::{Error, HasMetadata};
use libafl_bolts::impl_serdeany;
use serde::{Deserialize, Serialize};
use utf8_chars::BufReadCharsExt;

use crate::{options::LibfuzzerOptions, CustomMutationStatus};

#[derive(Deserialize, Serialize, Debug, Default)]
pub(crate) struct ShouldUseGrimoireMetadata {
    should: bool,
    non_utf8: usize,
    utf8: usize,
    checked: HashSet<PathBuf>,
}

impl_serdeany!(ShouldUseGrimoireMetadata);

impl ShouldUseGrimoireMetadata {
    pub fn should(&self) -> bool {
        self.should
    }
}

pub(crate) fn should_use_grimoire<S>(
    maybe_state: &mut Option<S>,
    options: &LibfuzzerOptions,
    mutator_status: &CustomMutationStatus,
) -> Result<Box<ShouldUseGrimoireMetadata>, Error>
where
    S: HasMetadata,
{
    let mut metadata: Box<ShouldUseGrimoireMetadata> = maybe_state
        .as_mut()
        .and_then(|state| state.metadata_map_mut().remove())
        .unwrap_or_default();
    let grimoire = if let Some(grimoire) = options.grimoire() {
        if grimoire && !mutator_status.std_mutational {
            eprintln!("WARNING: cowardly refusing to use grimoire after detecting the presence of a custom mutator");
        }
        metadata.should = grimoire && mutator_status.std_mutational;
        metadata
    } else if mutator_status.std_mutational {
        if options.dirs().is_empty() {
            eprintln!("WARNING: cowardly refusing to use grimoire since we cannot determine if the input is primarily text; set -grimoire=1 or provide a corpus directory.");
            metadata
        } else {
            let mut input_queue = VecDeque::new();
            input_queue.extend(options.dirs().iter().cloned());
            while let Some(entry) = input_queue.pop_front() {
                if entry.is_dir() {
                    if let Ok(entries) = std::fs::read_dir(entry) {
                        for entry in entries {
                            let entry = entry?;
                            input_queue.push_back(entry.path());
                        }
                    }
                } else if entry.is_file()
                    && entry
                        .extension()
                        .map_or(true, |ext| ext != "metadata" && ext != "lafl_lock")
                    && !metadata.checked.contains(&entry)
                {
                    let mut reader = std::io::BufReader::new(std::fs::File::open(&entry)?);
                    if reader.chars().all(|maybe_c| maybe_c.is_ok()) {
                        metadata.utf8 += 1;
                    } else {
                        metadata.non_utf8 += 1;
                    }
                    metadata.checked.insert(entry);
                }
            }
            metadata.should = metadata.utf8 > metadata.non_utf8; // greater-than so zero testcases doesn't enable
            if metadata.should {
                eprintln!("INFO: inferred grimoire mutator (found {}/{} UTF-8 inputs); if this is undesired, set -grimoire=0", metadata.utf8, metadata.utf8 + metadata.non_utf8);
            }
            metadata
        }
    } else {
        metadata
    };

    Ok(grimoire)
}
