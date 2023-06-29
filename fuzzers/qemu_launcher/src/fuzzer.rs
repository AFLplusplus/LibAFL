//! A libfuzzer-like fuzzer using qemu for binary-only coverage
//!
#[cfg(feature = "i386")]
use core::mem::size_of;
use core::{ptr::addr_of_mut, time::Duration};
use std::{env, path::PathBuf, process};

use clap::{builder::Str, Parser};
use libafl::{
    bolts::{
        core_affinity::Cores,
        current_nanos,
        launcher::Launcher,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::tuple_list,
        AsSlice,
    },
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{EventConfig, LlmpRestartingEventManager},
    executors::{ExitKind, TimeoutExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::{HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::StdMutationalStage,
    state::{HasCorpus, StdState},
    Error,
};
use libafl_qemu::{
    drcov::QemuDrCovHelper,
    edges::{edges_map_mut_slice, QemuEdgeCoverageHelper, MAX_EDGES_NUM},
    elf::EasyElf,
    emu::Emulator,
    MmapPerms, QemuExecutor, QemuHooks, QemuInstrumentationFilter, Regs,
};
use rangemap::RangeMap;

#[cfg(feature = "64bit")]
type GuestReg = u64;

#[cfg(not(feature = "64bit"))]
type GuestReg = u32;

#[derive(Default)]
pub struct Version;

impl From<Version> for Str {
    fn from(_: Version) -> Str {
        let version = [
            ("Architecture:", env!("CPU_TARGET")),
            ("Build Timestamp:", env!("VERGEN_BUILD_TIMESTAMP")),
            ("Describe:", env!("VERGEN_GIT_DESCRIBE")),
            ("Commit SHA:", env!("VERGEN_GIT_SHA")),
            ("Commit Date:", env!("VERGEN_RUSTC_COMMIT_DATE")),
            ("Commit Branch:", env!("VERGEN_GIT_BRANCH")),
            ("Rustc Version:", env!("VERGEN_RUSTC_SEMVER")),
            ("Rustc Channel:", env!("VERGEN_RUSTC_CHANNEL")),
            ("Rustc Host Triple:", env!("VERGEN_RUSTC_HOST_TRIPLE")),
            ("Rustc Commit SHA:", env!("VERGEN_RUSTC_COMMIT_HASH")),
            ("Cargo Target Triple", env!("VERGEN_CARGO_TARGET_TRIPLE")),
        ]
        .iter()
        .map(|(k, v)| format!("{k:25}: {v}\n"))
        .collect::<String>();

        format!("\n{version:}").into()
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[command(
    name = format!("qemu-coverage-{}",env!("CPU_TARGET")),
    version = Version::default(),
    about,
    long_about = "Tool for generating DrCov coverage data using QEMU instrumentation"
)]
pub struct FuzzerOptions {
    #[arg(long, help = "Coverage file")]
    coverage: String,

    #[arg(long, help = "Input directory")]
    input: String,

    #[arg(long, help = "Output directory")]
    output: String,

    #[arg(long, help = "Timeout in milli-seconds", default_value = "1000", value_parser = FuzzerOptions::parse_timeout)]
    timeout: Duration,

    #[arg(long = "port", help = "Broker port", default_value_t = 1337_u16)]
    port: u16,

    #[arg(long, help = "Cpu cores to use", default_value = "all", value_parser = Cores::from_cmdline)]
    cores: Cores,

    #[clap(short, long, help = "Enable output from the fuzzer clients")]
    verbose: bool,

    #[arg(last = true, help = "Arguments passed to the target")]
    args: Vec<String>,
}

impl FuzzerOptions {
    fn parse_timeout(src: &str) -> Result<Duration, Error> {
        Ok(Duration::from_millis(src.parse()?))
    }
}

pub fn fuzz() {
    let mut options = FuzzerOptions::parse();

    let output_dir = PathBuf::from(options.output);
    let corpus_dirs = [PathBuf::from(options.input)];

    let program = env::args().next().unwrap();
    println!("Program: {program:}");

    options.args.insert(0, program);
    println!("ARGS: {:#?}", options.args);

    env::remove_var("LD_LIBRARY_PATH");
    let env: Vec<(String, String)> = env::vars().collect();
    let emu = Emulator::new(&options.args, &env).unwrap();

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buffer).unwrap();

    let test_one_input_ptr = elf
        .resolve_symbol("LLVMFuzzerTestOneInput", emu.load_addr())
        .expect("Symbol LLVMFuzzerTestOneInput not found");
    println!("LLVMFuzzerTestOneInput @ {test_one_input_ptr:#x}");

    emu.set_breakpoint(test_one_input_ptr);
    unsafe { emu.run() };

    for m in emu.mappings() {
        println!(
            "Mapping: 0x{:016x}-0x{:016x}, {}",
            m.start(),
            m.end(),
            m.path().unwrap_or("<EMPTY>")
        );
    }

    let read_reg = |emu: &Emulator, reg: Regs| -> GuestReg {
        let val: GuestReg = emu.read_reg(reg).unwrap();

        #[cfg(feature = "be")]
        return GuestReg::from_be(val);

        #[cfg(not(feature = "be"))]
        return GuestReg::from_le(val);
    };

    let write_reg = |emu: &Emulator, reg: Regs, val: GuestReg| {
        #[cfg(feature = "be")]
        let val = GuestReg::to_be(val);

        #[cfg(not(feature = "be"))]
        let val = GuestReg::to_le(val);

        emu.write_reg(reg, val).unwrap();
    };

    println!("Break at {:#x}", read_reg(&emu, Regs::Pc));

    #[cfg(feature = "arm")]
    let ret_addr: u32 = read_reg(&emu, Regs::Lr);

    #[cfg(feature = "aarch64")]
    let ret_addr: u64 = read_reg(&emu, Regs::Lr);

    #[cfg(feature = "x86_64")]
    let stack_ptr: u64 = read_reg(&emu, Regs::Rsp);

    #[cfg(feature = "x86_64")]
    let ret_addr: u64 = {
        let mut ret_addr = [0; 8];
        unsafe { emu.read_mem(stack_ptr, &mut ret_addr) };
        u64::from_le_bytes(ret_addr)
    };

    #[cfg(feature = "i386")]
    let stack_ptr: u32 = read_reg(&emu, Regs::Esp);

    #[cfg(feature = "i386")]
    let ret_addr: u32 = {
        let mut ret_addr = [0; 4];
        unsafe { emu.read_mem(stack_ptr, &mut ret_addr) };
        u32::from_le_bytes(ret_addr)
    };

    #[cfg(feature = "mips")]
    let ret_addr: u32 = read_reg(&emu, Regs::Ra);

    #[cfg(feature = "ppc")]
    let ret_addr: u32 = read_reg(&emu, Regs::Lr);

    println!("Return address = {ret_addr:#x}");

    emu.remove_breakpoint(test_one_input_ptr);
    emu.set_breakpoint(ret_addr);

    let input_addr = emu.map_private(0, 4096, MmapPerms::ReadWrite).unwrap();
    println!("Placing input at {input_addr:#x}");

    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target
            .as_slice()
            .chunks(4096)
            .next()
            .expect("Failed to get chunk");
        let len = buf.len() as GuestReg;

        unsafe {
            emu.write_mem(input_addr, buf);

            #[cfg(feature = "arm")]
            {
                write_reg(&emu, Regs::R0, input_addr);
                write_reg(&emu, Regs::R1, len);
                write_reg(&emu, Regs::Pc, test_one_input_ptr);
                write_reg(&emu, Regs::Lr, ret_addr);
            }

            #[cfg(feature = "aarch64")]
            {
                write_reg(&emu, Regs::X0, input_addr);
                write_reg(&emu, Regs::X1, len);
                write_reg(&emu, Regs::Pc, test_one_input_ptr);
                write_reg(&emu, Regs::Lr, ret_addr);
            }

            #[cfg(feature = "x86_64")]
            {
                write_reg(&emu, Regs::Rdi, input_addr);
                write_reg(&emu, Regs::Rsi, len);
                write_reg(&emu, Regs::Rip, test_one_input_ptr);
                write_reg(&emu, Regs::Rsp, stack_ptr);
            }

            #[cfg(feature = "i386")]
            {
                let input_addr_bytes = input_addr.to_le_bytes();
                emu.write_mem(stack_ptr + (size_of::<u32>() as u32), &input_addr_bytes);

                let len_bytes = len.to_le_bytes();
                emu.write_mem(stack_ptr + ((2 * size_of::<u32>()) as u32), &len_bytes);

                write_reg(&emu, Regs::Eip, test_one_input_ptr);
                write_reg(&emu, Regs::Esp, stack_ptr);
            }

            #[cfg(feature = "mips")]
            {
                write_reg(&emu, Regs::A0, input_addr);
                write_reg(&emu, Regs::A1, len);
                write_reg(&emu, Regs::Pc, test_one_input_ptr);
                write_reg(&emu, Regs::Ra, ret_addr);
            }

            #[cfg(feature = "ppc")]
            {
                write_reg(&emu, Regs::R3, input_addr);
                write_reg(&emu, Regs::R4, len);
                write_reg(&emu, Regs::Pc, test_one_input_ptr);
                write_reg(&emu, Regs::Lr, ret_addr);
            }

            emu.run();
        }

        ExitKind::Ok
    };

    let mut run_client = |state: Option<_>, mut mgr: LlmpRestartingEventManager<_, _>, _core_id| {
        // Create an observation channel using the coverage map
        let edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                edges_map_mut_slice(),
                addr_of_mut!(MAX_EDGES_NUM),
            ))
        };

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::tracking(&edges_observer, true, false),
            // Time feedback, this one does not need a feedback state
            TimeFeedback::with_observer(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep it in memory for performance
                InMemoryCorpus::new(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(output_dir.clone()).unwrap(),
                // States of the feedbacks.
                // The feedbacks can report the data that should persist in the State.
                &mut feedback,
                // Same for objective feedbacks
                &mut objective,
            )
            .unwrap()
        });

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let rangemap = emu
            .mappings()
            .filter_map(|m| {
                m.path()
                    .map(|p| ((m.start() as usize)..(m.end() as usize), p.to_string()))
                    .filter(|(_, p)| !p.is_empty())
            })
            .enumerate()
            .fold(
                RangeMap::<usize, (u16, String)>::new(),
                |mut rm, (i, (r, p))| {
                    rm.insert(r, (i as u16, p));
                    rm
                },
            );

        let mut hooks = QemuHooks::new(
            &emu,
            tuple_list!(
                QemuEdgeCoverageHelper::default(),
                QemuDrCovHelper::new(
                    QemuInstrumentationFilter::None,
                    rangemap,
                    PathBuf::from(&options.coverage),
                    false,
                )
            ),
        );

        // Create a QEMU in-process executor
        let executor = QemuExecutor::new(
            &mut hooks,
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )
        .expect("Failed to create QemuExecutor");

        // Wrap the executor to keep track of the timeout
        let mut executor = TimeoutExecutor::new(executor, options.timeout);

        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
                .unwrap_or_else(|_| {
                    println!("Failed to load initial corpus at {:?}", &corpus_dirs);
                    process::exit(0);
                });
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        // Setup an havoc mutator with a mutational stage
        let mutator = StdScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        Ok(())
    };

    // The shared memory allocator
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    // The stats reporter for the broker
    let monitor = MultiMonitor::new(|s| println!("{s}"));

    // Build and run a Launcher
    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .broker_port(options.port)
        .configuration(EventConfig::from_build_id())
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&options.cores)
        .stdout_file(Some("/dev/null"))
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
}
