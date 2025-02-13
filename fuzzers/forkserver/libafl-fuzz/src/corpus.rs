use std::{
    borrow::Cow,
    fs::File,
    io,
    io::{BufRead, BufReader},
    path::Path,
};

use libafl::{
    corpus::{Corpus, CorpusId, Testcase},
    inputs::BytesInput,
    state::{HasCorpus, HasExecutions, HasSolutions, HasStartTime},
    Error,
};
use libafl_bolts::current_time;
use nix::{
    errno::Errno,
    fcntl::{Flock, FlockArg},
};

use crate::{fuzzer::LibaflFuzzState, OUTPUT_GRACE};

pub fn generate_base_filename(state: &mut LibaflFuzzState, id: CorpusId) -> String {
    let id = id.0;
    let is_seed = state.must_load_initial_inputs();
    let name = if is_seed {
        // TODO set orig filename
        format!("id:{id:0>6},time:0,execs:0,orig:TODO",)
    } else {
        // TODO: change hardcoded values of op (operation aka stage_name) & rep (amount of stacked mutations applied)
        let src = if let Some(parent_id) = state.corpus().current() {
            parent_id.0
        } else {
            0
        };
        let execs = *state.executions();
        let time = (current_time() - *state.start_time()).as_secs();
        format!("id:{id:0>6},src:{src:0>6},time:{time},execs:{execs},op:havoc,rep:0",)
    };
    name
}

// The function needs to be compatible with CustomFilepathToTestcaseFeedback
#[expect(clippy::unnecessary_wraps)]
pub fn set_corpus_filepath(
    state: &mut LibaflFuzzState,
    testcase: &mut Testcase<BytesInput>,
    _fuzzer_dir: &Path,
) -> Result<(), Error> {
    let id = state.corpus().peek_free_id();
    let mut name = generate_base_filename(state, id);
    if testcase.hit_feedbacks().contains(&Cow::Borrowed("edges")) {
        name = format!("{name},+cov");
    }
    *testcase.filename_mut() = Some(name);
    // We don't need to set the path since everything goes into one dir unlike with Objectives
    Ok(())
}

// The function needs to be compatible with CustomFilepathToTestcaseFeedback
#[expect(clippy::unnecessary_wraps)]
pub fn set_solution_filepath(
    state: &mut LibaflFuzzState,
    testcase: &mut Testcase<BytesInput>,
    output_dir: &Path,
) -> Result<(), Error> {
    // sig:0SIGNAL
    // TODO: verify if 0 time if objective found during seed loading
    let id = state.solutions().peek_free_id();
    let mut filename = generate_base_filename(state, id);
    let mut dir = "crashes";
    if testcase
        .hit_objectives()
        .contains(&Cow::Borrowed("TimeoutFeedback"))
    {
        filename = format!("{filename},+tout");
        dir = "hangs";
    }
    *testcase.file_path_mut() = Some(output_dir.join(dir).join(&filename));
    *testcase.filename_mut() = Some(filename);
    Ok(())
}

fn parse_time_line(line: &str) -> Result<u64, Error> {
    line.split(": ")
        .last()
        .ok_or(Error::illegal_state("invalid stats file"))?
        .parse()
        .map_err(|_| Error::illegal_state("invalid stats file"))
}

pub fn check_autoresume(fuzzer_dir: &Path, auto_resume: bool) -> Result<Flock<File>, Error> {
    if !fuzzer_dir.exists() {
        std::fs::create_dir(fuzzer_dir)?;
    }
    // lock the fuzzer dir
    let fuzzer_dir_fd = File::open(fuzzer_dir)?;
    let file = match Flock::lock(fuzzer_dir_fd, FlockArg::LockExclusiveNonblock) {
        Ok(l) => l,
        Err(err) => match err.1 {
            Errno::EWOULDBLOCK => return Err(Error::illegal_state(
                "Looks like the job output directory is being actively used by another instance",
            )),
            _ => {
                return Err(Error::last_os_error(
                    format!("Error creating lock for output dir: exit code {}", err.1).as_str(),
                ))
            }
        },
    };
    // Check if we have an existing fuzzed fuzzer_dir
    let stats_file = fuzzer_dir.join("fuzzer_stats");
    if stats_file.exists() {
        let file = File::open(&stats_file).unwrap();
        let reader = BufReader::new(file);
        let mut start_time: u64 = 0;
        let mut last_update: u64 = 0;
        for (index, line) in reader.lines().enumerate() {
            match index {
                // first line is start_time
                0 => {
                    start_time = parse_time_line(&line?).unwrap();
                }
                // second_line is last_update
                1 => {
                    last_update = parse_time_line(&line?).unwrap();
                }
                _ => break,
            }
        }
        if !auto_resume && last_update.saturating_sub(start_time) > OUTPUT_GRACE * 60 {
            return Err(Error::illegal_state("The job output directory already exists and contains results! use AFL_AUTORESUME=1 or provide \"-\" for -i "));
        }
    }
    if !auto_resume {
        let queue_dir = fuzzer_dir.join("queue");
        let hangs_dir = fuzzer_dir.join("hangs");
        let crashes_dir = fuzzer_dir.join("crashes");
        // Create our (sub) directories for Objectives & Corpus
        create_dir_if_not_exists(&crashes_dir).expect("should be able to create crashes dir");
        create_dir_if_not_exists(&hangs_dir).expect("should be able to create hangs dir");
        create_dir_if_not_exists(&queue_dir).expect("should be able to create queue dir");
    }
    Ok(file)
}

pub fn create_dir_if_not_exists(path: &Path) -> io::Result<()> {
    if path.is_file() {
        return Err(io::Error::new(
            // TODO: change this to ErrorKind::NotADirectory
            // when stabilitzed https://github.com/rust-lang/rust/issues/86442
            io::ErrorKind::Other,
            format!("{} expected a directory; got a file", path.display()),
        ));
    }
    match std::fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(err) => {
            if matches!(err.kind(), io::ErrorKind::AlreadyExists) {
                Ok(())
            } else {
                Err(err)
            }
        }
    }
}

#[cfg(not(feature = "fuzzbench"))]
pub fn remove_main_node_file(output_dir: &Path) -> Result<(), Error> {
    for entry in std::fs::read_dir(output_dir)?.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() && path.join("is_main_node").exists() {
            std::fs::remove_file(path.join("is_main_node"))?;
            return Ok(());
        }
    }
    Err(Error::illegal_state("main node's directory not found!"))
}
