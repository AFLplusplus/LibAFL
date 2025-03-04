use std::path::PathBuf;
use hashbrown::hash_map::Entry;
use hashbrown::HashMap;
use libafl_bolts::core_affinity::CoreId;
use regex::{Captures, Regex};
use crate::MulticoreDrive;
use std::fs;

#[derive(Debug, Clone)]
pub struct AugmentedCli {
    base_cli: Vec<String>,
    workdir: PathBuf,
    core_id: CoreId,
}

impl AugmentedCli {
    pub fn new(base_cli: Vec<String>, workdir: PathBuf, core_id: CoreId) -> Self {
        Self {
            base_cli,
            workdir,
            core_id
        }
    }

    pub fn parse(&self) -> Vec<String> {
        let mdisk_re = Regex::new(r"lqemu\(mdisk,(?<path>.*)\)").unwrap();
        let mdisk_path = self.workdir.join("disks");

        println!("removing {mdisk_path:?}");

        if mdisk_path.exists() {
            fs::remove_dir_all(&mdisk_path).unwrap();
        }

        fs::create_dir_all(&mdisk_path).unwrap();

        // old_path -> new_path
        let mut replacements: HashMap<PathBuf, PathBuf> = HashMap::new();

        for hay in &self.base_cli {
            for caps in mdisk_re.captures_iter(hay) {
                let (_, [mdisk_in_path]) = caps.extract();

                match replacements.entry(PathBuf::from(&mdisk_in_path)) {
                    Entry::Occupied(_) => {}
                    Entry::Vacant(new_entry) => {
                        let mut multicore_disk = MulticoreDrive::new(PathBuf::from(mdisk_in_path), mdisk_path.clone());
                        multicore_disk.push(&self.core_id).unwrap();
                        new_entry.insert(multicore_disk.push(&self.core_id).unwrap());
                    }
                }
            }
        }

        let mut new_cli = self.base_cli.clone();
        for s in &mut new_cli {
            *s = mdisk_re.replace_all(s, |caps: &Captures| {
                let path = PathBuf::from(&caps["path"]);
                replacements.get(&path).unwrap().as_os_str().to_str().unwrap().to_string()
            }).to_string();
        }

        new_cli
    }
}