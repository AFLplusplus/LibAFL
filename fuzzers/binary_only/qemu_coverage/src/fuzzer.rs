//! A libfuzzer-like fuzzer using qemu for binary-only coverage
//!
#[cfg(feature = "i386")]
use core::mem::size_of;
use core::time::Duration;
use std::{env, fmt::Write, fs::DirEntry, io, path::PathBuf, process};

use clap::{builder::Str, Parser};
use libafl::{
    corpus::{Corpus, NopCorpus},
    events::{
        launcher::Launcher, ClientDescription, EventConfig, EventRestarter,
        LlmpRestartingEventManager,
    },
    executors::ExitKind,
    fuzzer::StdFuzzer,
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    schedulers::QueueScheduler,
    state::{HasCorpus, StdState},
    Error,
};
use libafl_bolts::{
    core_affinity::Cores,
    os::unix_signals::Signal,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
    AsSlice,
};
use libafl_qemu::{
    elf::EasyElf,
    modules::{drcov::DrCovModule, StdAddressFilter},
    ArchExtras, CallingConvention, Emulator, GuestAddr, GuestReg, MmapPerms, Qemu, QemuExecutor,
    QemuExitReason, QemuRWError, QemuShutdownCause, Regs,
};

#[derive(Default)]
pub struct Version;

/// Parse a millis string to a [`Duration`]. Used for arg parsing.
fn timeout_from_millis_str(time: &str) -> Result<Duration, Error> {
    Ok(Duration::from_millis(time.parse()?))
}

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
        .fold(String::new(), |mut output, (k, v)| {
            let _ = writeln!(output, "{k:25}: {v}");
            output
        });

        format!("\n{version:}").into()
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[command(
    name = format!("qemu_coverage-{}",env!("CPU_TARGET")),
    version = Version::default(),
    about,
    long_about = "Module for generating DrCov coverage data using QEMU instrumentation"
)]
pub struct FuzzerOptions {
    #[arg(long, help = "Coverage file")]
    coverage_path: PathBuf,

    #[arg(long, help = "Input directory")]
    input_dir: PathBuf,

    #[arg(long, help = "Timeout in seconds", default_value = "5000", value_parser = timeout_from_millis_str)]
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

pub const MAX_INPUT_SIZE: usize = 1048576; // 1MB

pub fn fuzz() {
    let mut options = FuzzerOptions::parse();

    let corpus_files = options
        .input_dir
        .read_dir()
        .expect("Failed to read corpus dir")
        .collect::<Result<Vec<DirEntry>, io::Error>>()
        .expect("Failed to read dir entry");

    let num_files = corpus_files.len();
    let num_cores = options.cores.ids.len();
    let files_per_core = (num_files as f64 / num_cores as f64).ceil() as usize;

    let program = env::args().next().unwrap();
    log::debug!("Program: {program:}");

    options.args.insert(0, program);
    log::debug!("ARGS: {:#?}", options.args);

    env::remove_var("LD_LIBRARY_PATH");

    let qemu = Qemu::init(&options.args).unwrap();

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer).unwrap();

    let test_one_input_ptr = elf
        .resolve_symbol("LLVMFuzzerTestOneInput", qemu.load_addr())
        .expect("Symbol LLVMFuzzerTestOneInput not found");
    log::debug!("LLVMFuzzerTestOneInput @ {test_one_input_ptr:#x}");

    qemu.entry_break(test_one_input_ptr);

    for m in qemu.mappings() {
        log::debug!(
            "Mapping: 0x{:016x}-0x{:016x}, {}",
            m.start(),
            m.end(),
            m.path().unwrap_or(&"<EMPTY>".to_string())
        );
    }

    let pc: GuestReg = qemu.read_reg(Regs::Pc).unwrap();
    log::debug!("Break at {pc:#x}");

    let ret_addr: GuestAddr = qemu.read_return_address().unwrap();
    log::debug!("Return address = {ret_addr:#x}");

    qemu.set_breakpoint(ret_addr);

    let input_addr = qemu
        .map_private(0, MAX_INPUT_SIZE, MmapPerms::ReadWrite)
        .unwrap();
    log::debug!("Placing input at {input_addr:#x}");

    let stack_ptr: GuestAddr = qemu.read_reg(Regs::Sp).unwrap();

    let reset = |buf: &[u8], len: GuestReg| -> Result<(), QemuRWError> {
        unsafe {
            let _ = qemu.write_mem(input_addr, buf);
            qemu.write_reg(Regs::Pc, test_one_input_ptr)?;
            qemu.write_reg(Regs::Sp, stack_ptr)?;
            qemu.write_return_address(ret_addr)?;
            qemu.write_function_argument(CallingConvention::Cdecl, 0, input_addr)?;
            qemu.write_function_argument(CallingConvention::Cdecl, 1, len)?;

            match qemu.run() {
                Ok(QemuExitReason::Breakpoint(_)) => {}
                Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(Signal::SigInterrupt))) => {
                    process::exit(0)
                }
                _ => panic!("Unexpected QEMU exit."),
            }

            Ok(())
        }
    };

    let mut harness =
        |_emulator: &mut Emulator<_, _, _, _, _>, _state: &mut _, input: &BytesInput| {
            let target = input.target_bytes();
            let mut buf = target.as_slice();
            let mut len = buf.len();
            if len > MAX_INPUT_SIZE {
                buf = &buf[0..MAX_INPUT_SIZE];
                len = MAX_INPUT_SIZE;
            }
            let len = len as GuestReg;
            reset(buf, len).unwrap();
            ExitKind::Ok
        };

    let mut run_client = |state: Option<_>,
                          mut mgr: LlmpRestartingEventManager<_, _, _>,
                          client_description: ClientDescription| {
        let core_id = client_description.core_id();
        let core_idx = options
            .cores
            .position(core_id)
            .expect("Failed to get core index");
        let files = corpus_files
            .iter()
            .skip(files_per_core * core_idx)
            .take(files_per_core)
            .map(|x| x.path())
            .collect::<Vec<PathBuf>>();

        if files.is_empty() {
            mgr.send_exiting()?;
            Err(Error::ShuttingDown)?
        }

        #[allow(clippy::let_unit_value)]
        let mut feedback = ();

        #[allow(clippy::let_unit_value)]
        let mut objective = ();

        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                StdRand::new(),
                NopCorpus::new(),
                NopCorpus::new(),
                &mut feedback,
                &mut objective,
            )
            .unwrap()
        });

        let scheduler = QueueScheduler::new();
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut cov_path = options.coverage_path.clone();
        let coverage_name = cov_path.file_stem().unwrap().to_str().unwrap();
        let coverage_extension = cov_path.extension().unwrap_or_default().to_str().unwrap();
        let core = core_id.0;
        cov_path.set_file_name(format!("{coverage_name}-{core:03}.{coverage_extension}"));

        let emulator_modules = tuple_list!(DrCovModule::builder()
            .filter(StdAddressFilter::default())
            .filename(cov_path)
            .full_trace(false)
            .build());

        let emulator = Emulator::empty()
            .qemu(qemu)
            .modules(emulator_modules)
            .build()?;

        let mut executor = QemuExecutor::new(
            emulator,
            &mut harness,
            (),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            options.timeout,
        )
        .expect("Failed to create QemuExecutor");

        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs_by_filenames(&mut fuzzer, &mut executor, &mut mgr, &files)
                .unwrap_or_else(|_| {
                    println!("Failed to load initial corpus at {:?}", &options.input_dir);
                    process::exit(0);
                });
            log::debug!("We imported {} inputs from disk.", state.corpus().count());
        }

        log::debug!("Processed {} inputs from disk.", files.len());

        mgr.send_exiting()?;
        Err(Error::ShuttingDown)?
    };

    match Launcher::builder()
        .shmem_provider(StdShMemProvider::new().expect("Failed to init shared memory"))
        .broker_port(options.port)
        .configuration(EventConfig::from_build_id())
        .monitor(MultiMonitor::new(|s| println!("{s}")))
        .run_client(&mut run_client)
        .cores(&options.cores)
        .stdout_file(if options.verbose {
            None
        } else {
            Some("/dev/null")
        })
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Run finished successfully."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
}
