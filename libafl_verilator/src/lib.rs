use std::{
    fs::File,
    io::{BufRead, BufReader, Seek, SeekFrom},
    os::fd::FromRawFd,
};

use hashbrown::{hash_map::Entry, HashMap};
use libafl::{
    bolts::{tuples::Named, AsIter, HasLen},
    executors::ExitKind,
    inputs::UsesInput,
    observers::{hash_slice, MapObserver, Observer},
    Error,
};
use nix::{fcntl::OFlag, sys::stat::Mode, NixPath};
use serde::{Deserialize, Serialize};

mod wrapper {
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(unused)]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use wrapper::*;

static mut COVERAGE_FILE: Option<File> = None;

pub unsafe fn initialize_coverage_file<P: ?Sized + NixPath>(dir: &P) -> Result<(), Error> {
    if COVERAGE_FILE.is_some() {
        return Err(Error::unsupported(
            "The coverage file may only be initialized once.",
        ));
    }
    let fd = nix::fcntl::open(
        dir,
        OFlag::O_TMPFILE | OFlag::O_RDWR | OFlag::O_EXCL,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|errno| {
        Error::unknown(format!(
            "Couldn't create the temporary coverage file; got {:?}: {}",
            &errno,
            errno.desc()
        ))
    })?;
    __libafl_set_coverage_file_fd(fd);
    COVERAGE_FILE = Some(File::from_raw_fd(fd));
    Ok(())
}

fn get_coverage_file() -> Result<File, Error> {
    unsafe {
        loop {
            if let Some(file) = COVERAGE_FILE.as_mut() {
                file.seek(SeekFrom::Start(0))?; // reseek to the beginning
                return Ok(file.try_clone()?);
            }
            initialize_coverage_file("/tmp")?;
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VerilatorMapObserver {
    mapping: HashMap<Vec<u8>, usize>,
    map: Vec<usize>,
    name: String,
}

impl VerilatorMapObserver {
    pub fn new(name: String) -> Self {
        Self {
            name,
            mapping: Default::default(),
            map: Default::default(),
        }
    }

    fn process_verilator_coverage(&mut self) -> Result<(), Error> {
        for line in BufReader::new(get_coverage_file()?).split(b'\n') {
            let line = line?;
            if line[0] == b'C' {
                let mut separator = line.len();
                for &entry in line.iter().rev() {
                    if entry == b' ' {
                        break;
                    }
                    separator -= 1;
                }
                let (name, count) = line.split_at(separator);
                let name = Vec::from(&name[3..(name.len() - 2)]); // "C '...' "
                let count = std::str::from_utf8(count)
                    .map_err(|_| Error::illegal_state("Couldn't parse the coverage count value!"))?
                    .parse()?;
                match self.mapping.entry(name) {
                    Entry::Occupied(e) => {
                        let idx = *e.get();
                        self.map[idx] = count;
                    }
                    Entry::Vacant(e) => {
                        e.insert(self.map.len());
                        self.map.push(count);
                    }
                }
            }
        }
        Ok(())
    }
}

impl HasLen for VerilatorMapObserver {
    fn len(&self) -> usize {
        self.map.len()
    }

    fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl Named for VerilatorMapObserver {
    fn name(&self) -> &str {
        &self.name
    }
}

impl MapObserver for VerilatorMapObserver {
    type Entry = usize;

    fn get(&self, idx: usize) -> &Self::Entry {
        self.map.get(idx).unwrap()
    }

    fn get_mut(&mut self, idx: usize) -> &mut Self::Entry {
        self.map.get_mut(idx).unwrap()
    }

    fn usable_count(&self) -> usize {
        self.map.len()
    }

    fn count_bytes(&self) -> u64 {
        self.map.iter().filter(|&&e| e != self.initial()).count() as u64
    }

    fn hash(&self) -> u64 {
        hash_slice(&self.map)
    }

    #[inline(always)]
    fn initial(&self) -> Self::Entry {
        0
    }

    fn reset_map(&mut self) -> Result<(), Error> {
        let len = self.map.len();
        self.map.clear();
        self.map.resize(len, 0);
        Ok(())
    }

    fn to_vec(&self) -> Vec<Self::Entry> {
        self.map.clone()
    }

    fn how_many_set(&self, indexes: &[usize]) -> usize {
        indexes
            .into_iter()
            .map(|&idx| self.get(idx))
            .filter(|&&e| e != self.initial())
            .count()
    }
}

impl<S> Observer<S> for VerilatorMapObserver
where
    S: UsesInput,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        unsafe {
            __libafl_reset_verilator_coverage();
        }
        self.reset_map()
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        unsafe {
            __libafl_process_verilator_coverage();
        }
        self.process_verilator_coverage()
    }

    fn pre_exec_child(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.reset_map() // we do not need to use __libafl_reset_verilator_coverage() because we fork
    }

    fn post_exec_child(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.post_exec(state, input, exit_kind)
    }
}

impl<'it> AsIter<'it> for VerilatorMapObserver {
    type Item = usize;
    type IntoIter = core::slice::Iter<'it, Self::Item>;

    fn as_iter(&'it self) -> Self::IntoIter {
        self.map.iter()
    }
}

#[cfg(test)]
mod test {
    use std::io::Write;

    use libafl::{inputs::NopInput, state::NopState};

    use super::*;

    #[link(name = "afl-verilator-test", kind = "static")]
    extern "C" {}

    #[test]
    fn can_read_coverage() -> Result<(), Error> {
        let mut state = NopState::<NopInput>::default();
        let input = NopInput;
        let mut obs = VerilatorMapObserver::new("test-observer".to_string());
        let mut cov_file = get_coverage_file()?;
        cov_file.write_all(include_bytes!("../test-files/coverage.dat"))?;

        obs.pre_exec(&mut state, &input)?;
        obs.process_verilator_coverage()?; // post-exec invokes verilator, which we don't want :)
        println!("obs: {:?}", obs);

        assert_eq!(*obs.get(0), 1);

        let mut cov_file = get_coverage_file()?;
        cov_file.write_all(include_bytes!("../test-files/coverage2.dat"))?;

        obs.pre_exec(&mut state, &input)?;
        obs.process_verilator_coverage()?;
        println!("obs: {:?}", obs);

        assert_eq!(*obs.get(0), 2);

        Ok(())
    }
}
