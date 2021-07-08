//! A singlethreaded QEMU fuzzer that can auto-restart.

use clap::{App, Arg};

use core::time::Duration;
use std::{
    env,
    fs::{self},
    path::PathBuf,
};

use libafl::{
    bolts::{
        current_nanos,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::tuple_list,
    },
    corpus::{Corpus, OnDiskCorpus, QueueCorpusScheduler},
    events::SimpleRestartingEventManager,
    executors::ExitKind,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::{HitcountsMapObserver, VariableMapObserver},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, StdState},
    stats::SimpleStats,
    Error,
};
use libafl_qemu::{
    amd64::Amd64Regs, elf::EasyElf, emu, filter_qemu_args, hooks, MmapPerms, QemuExecutor,
};

/// The fuzzer main (as `no_mangle` C function)
#[no_mangle]
pub fn libafl_qemu_main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    //RegistryBuilder::register::<Tokens>();

    let res = match App::new("libafl_qemu_fuzzbench")
        .version("0.4.0")
        .author("AFLplusplus team")
        .about("LibAFL-based fuzzer with QEMU for Fuzzbench")
        .arg(
            Arg::new("out")
                .about("The directory to place finds in ('corpus')")
                .long("libafl-out")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("in")
                .about("The directory to read initial inputs from ('seeds')")
                .long("libafl-in")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("tokens")
                .long("libafl-tokens")
                .about("A file to read tokens from, to be used during fuzzing")
                .takes_value(true),
        )
        .arg(
            Arg::new("logfile")
                .long("libafl-logfile")
                .about("Duplicates all output to this file")
                .default_value("libafl.log"),
        )
        .arg(
            Arg::new("timeout")
                .long("libafl-timeout")
                .about("Timeout for each individual execution, in milliseconds")
                .default_value("1000"),
        )
        .try_get_matches_from(filter_qemu_args())
    {
        Ok(res) => res,
        Err(err) => {
            println!(
                "Syntax: {}, --libafl-in <input> --libafl-out <output>\n{:?}",
                env::current_exe()
                    .unwrap_or_else(|_| "fuzzer".into())
                    .to_string_lossy(),
                err.info,
            );
            return;
        }
    };

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    // For fuzzbench, crashes and finds are inside the same `corpus` directory, in the "queue" and "crashes" subdir.
    let mut out_dir = PathBuf::from(res.value_of("out").unwrap().to_string());
    if fs::create_dir(&out_dir).is_err() {
        println!("Out dir at {:?} already exists.", &out_dir);
        if !out_dir.is_dir() {
            println!("Out dir at {:?} is not a valid directory!", &out_dir);
            return;
        }
    }
    let mut crashes = out_dir.clone();
    crashes.push("crashes");
    out_dir.push("queue");

    let in_dir = PathBuf::from(res.value_of("in").unwrap().to_string());
    if !in_dir.is_dir() {
        println!("In dir at {:?} is not a valid directory!", &in_dir);
        return;
    }

    let tokens = res.value_of("tokens").map(PathBuf::from);

    let logfile = PathBuf::from(res.value_of("logfile").unwrap().to_string());

    let timeout = Duration::from_millis(
        res.value_of("timeout")
            .unwrap()
            .to_string()
            .parse()
            .expect("Could not parse timeout in milliseconds"),
    );

    fuzz(out_dir, crashes, in_dir, tokens, logfile, timeout)
        .expect("An error occurred while fuzzing");
}

/// The actual fuzzer
fn fuzz(
    corpus_dir: PathBuf,
    objective_dir: PathBuf,
    _seed_dir: PathBuf,
    _tokenfile: Option<PathBuf>,
    _logfile: PathBuf,
    _timeout: Duration,
) -> Result<(), Error> {
    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(emu::binary_path(), &mut elf_buffer)?;

    let test_one_input_ptr = elf.resolve_symbol("LLVMFuzzerTestOneInput").unwrap();
    println!("LLVMFuzzerTestOneInput @ {:#x}", test_one_input_ptr);

    emu::set_breakpoint(test_one_input_ptr); // LLVMFuzzerTestOneInput
    emu::run();

    println!(
        "Break at {:#x}",
        emu::read_reg::<_, u64>(Amd64Regs::Rip).unwrap()
    );

    let stack_ptr: u64 = emu::read_reg(Amd64Regs::Rsp).unwrap();
    let mut ret_addr = [0u64];
    emu::read_mem(stack_ptr, &mut ret_addr);
    let ret_addr = ret_addr[0];

    println!("Stack pointer = {:#x}", stack_ptr);
    println!("Return address = {:#x}", ret_addr);

    emu::remove_breakpoint(test_one_input_ptr); // LLVMFuzzerTestOneInput
    emu::set_breakpoint(ret_addr); // LLVMFuzzerTestOneInput ret addr

    let input_addr = emu::map_private(0, 4096, MmapPerms::ReadWrite).unwrap();
    println!("Placing input at {:#x}", input_addr);

    let stats = SimpleStats::new(|s| {
        println!("{}", s);
    });

    let mut shmem_provider = StdShMemProvider::new()?;

    let (state, mut mgr) = match SimpleRestartingEventManager::launch(stats, &mut shmem_provider) {
        // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
        Ok(res) => res,
        Err(err) => match err {
            Error::ShuttingDown => {
                return Ok(());
            }
            _ => {
                panic!("Failed to setup the restarter: {}", err);
            }
        },
    };

    // Create an observation channel using the coverage map
    let edges = unsafe { &mut hooks::EDGES_MAP };
    let edges_counter = unsafe { &mut hooks::MAX_EDGES_NUM };
    let edges_observer =
        HitcountsMapObserver::new(VariableMapObserver::new("edges", edges, edges_counter));

    // The state of the edges feedback.
    let feedback_state = MapFeedbackState::with_observer(&edges_observer);

    // New maximization map feedback linked to the edges observer and the feedback state
    let feedback = MaxMapFeedback::new(&feedback_state, &edges_observer);

    // A feedback to choose if an input is a solution or not
    let objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            OnDiskCorpus::new(corpus_dir).unwrap(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir).unwrap(),
            // States of the feedbacks.
            // They are the data related to the feedbacks that you want to persist in the State.
            tuple_list!(feedback_state),
        )
    });

    // A queue policy to get testcasess from the corpus
    let scheduler = QueueCorpusScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let mut buf = target.as_slice();
        if buf.len() > 32 {
            buf = &buf[0..32];
        }

        emu::write_mem(input_addr, buf);

        emu::write_reg(Amd64Regs::Rdi, input_addr).unwrap();
        emu::write_reg(Amd64Regs::Rsi, buf.len()).unwrap();
        emu::write_reg(Amd64Regs::Rip, test_one_input_ptr).unwrap();
        emu::write_reg(Amd64Regs::Rsp, stack_ptr).unwrap();

        emu::run();

        ExitKind::Ok
    };

    // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
    let mut executor = QemuExecutor::new(
        &mut harness,
        tuple_list!(edges_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )?;

    executor.hook_edge_generation(hooks::gen_unique_edges_id);
    executor.hook_edge_execution(hooks::exec_log_hitcount);

    if state.corpus().count() < 1 {
        // Generator of printable bytearrays of max size 32
        let mut generator = RandPrintablesGenerator::new(32);

        // Generate 8 initial inputs
        state
            .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
            .expect("Failed to generate the initial corpus");
    }

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");

    // Never reached
    Ok(())
}
