use std::{
    ffi::CString,
    fs::File,
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    net::SocketAddr,
    os::fd::{FromRawFd, RawFd},
    path::PathBuf,
};

use clap::{self, Parser};
use goblin::elf::Elf;
use libafl::{
    bolts::{current_nanos, AsSlice},
    corpus::{Corpus, InMemoryCorpus},
    events::EventConfig,
    executors::{ExitKind, InProcessForkExecutor},
    feedback_or,
    feedbacks::{MaxMapFeedback, TimeFeedback},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::{MultiMonitor, OnDiskTOMLMonitor},
    mutators::StdScheduledMutator,
    prelude::{
        havoc_mutations, tuple_list, Cores, Launcher, ShMemProvider, StdRand, StdShMemProvider,
        TimeObserver,
    },
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, StdWeightedScheduler,
    },
    stages::{CalibrationStage, StdPowerMutationalStage},
    state::{HasCorpus, HasMaxSize, StdState},
    Error, Fuzzer, StdFuzzer,
};
use libafl_verilator::VerilatorMapObserver;
use mimalloc::MiMalloc;
use nix::{fcntl::OFlag, sys::stat::Mode};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

const BASE_EXECUTABLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/base-executable"));

mod wrapper {
    #![allow(non_snake_case)]
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(unused)]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use wrapper::*;

const MAX_CYCLES: usize = 1 << 12;

// create a temporary file which will be deleted on process death or close
fn create_input_file() -> Result<(RawFd, File), Error> {
    let input_fd = nix::fcntl::open(
        "/tmp",
        OFlag::O_TMPFILE | OFlag::O_RDWR,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|errno| {
        Error::unknown(format!(
            "Couldn't create the temporary input file; got {:?}: {}",
            &errno,
            errno.desc()
        ))
    })?;
    let input_file = unsafe { File::from_raw_fd(input_fd) };

    Ok((input_fd, input_file))
}

/// The commandline args this fuzzer accepts
#[derive(Debug, Parser)]
#[command(
    name = "libfuzzer_libpng_launcher",
    about = "A libfuzzer-like fuzzer for libpng with llmp-multithreading support and a launcher",
    author = "Addison Crump <research@addisoncrump.info>"
)]
struct Opt {
    #[arg(
    short,
    long,
    value_parser = Cores::from_cmdline,
    help = "Spawn a client in each of the provided cores. Broker runs in the 0th core. 'all' to select all available cores. 'none' to run a client without binding to any core. eg: '1,2-4,6' selects the cores 1,2,3,4,6.",
    name = "CORES"
    )]
    cores: Cores,

    #[arg(
        short = 'p',
        long,
        help = "Choose the broker TCP port, default is 1337",
        name = "PORT",
        default_value = "1337"
    )]
    broker_port: u16,

    #[arg(short = 'a', long, help = "Specify a remote broker", name = "REMOTE")]
    remote_broker_addr: Option<SocketAddr>,

    #[arg(short, long, help = "Set an initial corpus directory", name = "INPUT")]
    input: Vec<PathBuf>,

    #[arg(
        short,
        long,
        help = "Set the output directory, default is ./out",
        name = "OUTPUT",
        default_value = "./out"
    )]
    output: PathBuf,
}

fn main() -> Result<(), Error> {
    let opt = Opt::parse();

    let broker_port = opt.broker_port;
    let cores = opt.cores;

    // identify the region in the base executable we are executing "interesting" instructions in
    let elf = Elf::parse(BASE_EXECUTABLE).unwrap();
    let sym = elf
        .syms
        .iter()
        .find(|sym| elf.strtab.get_at(sym.st_name) == Some("INPUT_BUF"))
        .unwrap();
    let target_address = sym.st_value;
    drop(elf);

    let (input_fd, mut elf_input) = create_input_file()?;
    let input_filename = CString::new(format!("/proc/self/fd/{}", input_fd)).unwrap();

    // write the base executable
    elf_input.write_all(BASE_EXECUTABLE).unwrap();

    println!("Initialising CVA6, this may take some time...");
    // this starts CVA6 with the base executable we just wrote
    unsafe {
        __libafl_ariane_start(input_filename.as_ptr());
    }
    // make the trace file for the target a non-blocking pipe
    let trace_file = {
        let mut readdir = std::fs::read_dir("/proc/self/fd").unwrap();
        loop {
            let fd = readdir.next().unwrap()?;
            if let Ok(linked) = std::fs::read_link(fd.path()) {
                if linked.ends_with("trace_hart_00.dasm") {
                    // this fd is the trace for the hart
                    // we need to "convince" the hart to use a pipe instead
                    let (read, write) = nix::unistd::pipe2(OFlag::O_NONBLOCK).unwrap();
                    let trace_fd: RawFd = fd.file_name().to_str().unwrap().parse().unwrap();
                    nix::unistd::fsync(trace_fd).unwrap();
                    nix::unistd::dup2(write, trace_fd).unwrap();
                    nix::unistd::close(write).unwrap();
                    println!("overwrote the trace file at fd {} with a pipe", trace_fd);
                    let trace_file = unsafe { File::from_raw_fd(read) };
                    break trace_file;
                }
            }
        }
    };

    let mut reader = BufReader::new(trace_file);
    let mut line = String::new();
    let mut nops = 0;

    // pump the CPU of instructions until we hit the signal region, which is a large sequence of
    // nops. This ensures we fully load the executable. See cva6-base.c for details.
    'pumploop: loop {
        loop {
            match reader.read_line(&mut line) {
                Err(e) if e.kind() != ErrorKind::WouldBlock => {
                    // the model has not written to the trace yet; keep pumping!
                    panic!("Illegal error encountered while processing: {}", e);
                }
                Ok(_) => {
                    // in machine mode: c.nop or nop, might change by compiler
                    if line.contains("0x8000")
                        && (line.trim_end().ends_with("DASM(00000001)")
                            || line.trim_end().contains("DASM(00000013)"))
                    {
                        nops += 1;
                    } else {
                        nops = 0;
                    }
                    line.clear();
                }
                _ => {
                    if nops > 32 {
                        break 'pumploop;
                    }
                    break;
                }
            }
        }
        unsafe {
            __libafl_ariane_tick();
        }
    }
    drop(elf_input);

    // commit some very sinful acts against the verilator gods here
    // we write directly to the hart memory -- because it refuses to let us do this the right way
    // I have tried for multiple days to get the debug transfer module working in a way that is
    // sufficiently quick, to no avail. It is with a heavy heart that I must bully verilator into
    // doing my will in such a disgraceful way. I am ashamed.

    // iterate over all memory spaces in the program to identify the location of the input buffer
    let mem = File::open("/proc/self/maps")?;
    const NEEDLE: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

    // when we write to this input buffer in the future, we write directly into the design's memory
    // this is definitely unintended, but the alternative (dtm-based writes) take roughly the same
    // amount of time as just initialising the design from scratch :(
    let input_buffer = {
        let mut lines = BufReader::new(mem).lines();
        'searchloop: loop {
            let line = lines.next().unwrap().unwrap();
            let mut split = line.split_ascii_whitespace();
            let range = split.next().unwrap();
            let perms = split.next().unwrap();
            if perms.contains("rw") && split.nth(3).is_none() {
                // look for rw unnamed regions
                let (start, end) = range.split_once('-').unwrap();
                let start = usize::from_str_radix(start, 16).unwrap();
                let end = usize::from_str_radix(end, 16).unwrap();
                let pointer = start as *mut u8;
                // forgive me
                let mut region = unsafe { std::slice::from_raw_parts(pointer, end - start) };
                while let Some(offset) = memchr::memmem::find(region, &NEEDLE) {
                    unsafe {
                        let target = pointer.offset(offset as isize);

                        // check if this is the actual target, which has 1,2,3,4 after it
                        let checked = target.offset(4);
                        let checked_slice = std::slice::from_raw_parts(checked, 4);
                        let mut valid = true;
                        for (i, v) in (1..).zip(checked_slice) {
                            if i != *v {
                                valid = false;
                            }
                        }

                        if valid {
                            // super unsound...
                            break 'searchloop std::slice::from_raw_parts_mut(target, 1 << 12);
                        } else {
                            region = &region[(offset + 1)..];
                        }
                    }
                }
            }
        }
    };
    println!("Initialised CVA6, ready to fuzz!");

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    let monitor = OnDiskTOMLMonitor::new(
        "./fuzzer_stats.toml",
        MultiMonitor::new(|s| println!("{}", s)),
    );

    let mut run_client = |state: Option<_>, mut mgr, _core_id| {
        // observe the verilator coverage
        let cov_observer = VerilatorMapObserver::new("verilated-edges".to_string(), true)?;

        let time_observer = TimeObserver::new("time");

        let cov_feedback = MaxMapFeedback::new_tracking(&cov_observer, true, false);

        let calibration = CalibrationStage::new(&cov_feedback);

        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            cov_feedback,
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new_with_observer(&time_observer)
        );

        // no objective feedback at this time :(
        let mut objective = ();

        let mut state = if let Some(existing) = state {
            existing
        } else {
            StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep it in memory for performance
                InMemoryCorpus::new(),
                // Corpus in which we store solutions, but none are actually collected here
                InMemoryCorpus::new(),
                // States of the feedbacks.
                // The feedbacks can report the data that should persist in the State.
                &mut feedback,
                // Same for objective feedbacks
                &mut objective,
            )?
        };
        // stay well within our input buffer's size bound
        state.set_max_size(1 << 9);

        let mutator = StdScheduledMutator::new(havoc_mutations());
        let power = StdPowerMutationalStage::new(mutator, &cov_observer);

        let mut stages = tuple_list!(calibration, power);

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler = IndexesLenTimeMinimizerScheduler::new(StdWeightedScheduler::with_schedule(
            PowerSchedule::FAST,
        ));

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut harness = |input: &BytesInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();

            let mut actual = Vec::with_capacity(
                (buf.len() / core::mem::size_of::<u16>() + 8) * core::mem::size_of::<u16>(),
            );
            actual.extend_from_slice(buf);
            if actual.len() % core::mem::size_of::<u16>() != 0 {
                actual.push(0); // align to smallest instruction width
            }
            for _ in 0..7 {
                // provide many c.rets just in case of an incomplete long instruction
                actual.extend_from_slice(&0x8082u16.to_le_bytes()); // c.ret
            }

            input_buffer[..actual.len()].copy_from_slice(&actual);

            let mut entered_execution_zone = false;
            let mut in_execution_zone = false;
            // pump instructions for MAX_CYCLES cycles, or as long as we remain within our intended
            // execution region
            'pumploop: for _ in 0..MAX_CYCLES {
                loop {
                    match reader.read_line(&mut line) {
                        Err(e) if e.kind() != ErrorKind::WouldBlock => {
                            panic!("Encountered IO error while processing: {}", e);
                        }
                        Ok(_) => {
                            let trimmed = line.trim();
                            let mut split = trimmed.split_ascii_whitespace().skip(1);
                            // because of the fork, the trace file is not guaranteed to be particularly clean
                            if let Some(pc) = split.next().and_then(|pc| pc.strip_prefix("0x")) {
                                let pc = usize::from_str_radix(pc, 16).unwrap();

                                if pc > target_address as usize
                                    && pc < (target_address as usize + actual.len())
                                {
                                    entered_execution_zone = true;
                                    in_execution_zone = true;
                                } else {
                                    in_execution_zone = false;
                                }
                            }

                            line.clear();
                        }
                        _ => {
                            if entered_execution_zone && !in_execution_zone {
                                break 'pumploop;
                            }
                            break;
                        }
                    }
                }
                unsafe {
                    __libafl_ariane_tick();
                }
            }

            unsafe {
                __libafl_ariane_terminate();
            }
            while unsafe { !__libafl_ariane_terminated() } {
                loop {
                    match reader.read_line(&mut line) {
                        Err(e) if e.kind() != ErrorKind::WouldBlock => {
                            panic!("Encountered IO error while processing: {}", e);
                        }
                        Ok(_) => {
                            line.clear();
                        }
                        _ => {
                            break;
                        }
                    }
                }
                unsafe {
                    __libafl_ariane_tick();
                }
            }
            unsafe {
                __libafl_ariane_finalize();
            }
            reader.read_to_string(&mut line).ok(); // clean out the remaining data

            ExitKind::Ok
        };

        let shmem = StdShMemProvider::new()?;

        // fork executor so that we start at the point we left off at when we pumped the model
        let mut executor = InProcessForkExecutor::new(
            &mut harness,
            tuple_list!(cov_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            shmem,
        )?;

        if state.corpus().is_empty() {
            let mut generator = RandBytesGenerator::new(32);
            state.generate_initial_inputs(
                &mut fuzzer,
                &mut executor,
                &mut generator,
                &mut mgr,
                4,
            )?;
            println!("Generated {} initial inputs", state.corpus().count());
        }

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

        Ok(())
    };

    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::AlwaysUnique) // different coverage mappings
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .broker_port(broker_port)
        .remote_broker_addr(opt.remote_broker_addr)
        .stdout_file(Some("/dev/null"))
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {:?}", err),
    }

    Ok(())
}
