//! A libfuzzer-like fuzzer using qemu for binary-only coverage
//!
#[cfg(feature = "i386")]
use core::mem::size_of;
use std::{env, fmt::Write, io, path::PathBuf, process, ptr::NonNull};

use clap::{builder::Str, Parser};
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, NopCorpus},
    events::{EventRestarter, SimpleRestartingEventManager},
    executors::ExitKind,
    feedbacks::MaxMapFeedback,
    fuzzer::StdFuzzer,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    observers::{ConstMapObserver, HitcountsMapObserver},
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
    AsSlice, AsSliceMut,
};
use libafl_qemu::{
    elf::EasyElf, modules::edges::StdEdgeCoverageChildModule, ArchExtras, CallingConvention,
    Emulator, GuestAddr, GuestReg, MmapPerms, Qemu, QemuExitError, QemuExitReason,
    QemuForkExecutor, QemuShutdownCause, Regs,
};
use libafl_targets::{EDGES_MAP_DEFAULT_SIZE, EDGES_MAP_PTR};

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
name = format ! ("qemu_cmin-{}", env ! ("CPU_TARGET")),
version = Version::default(),
about,
long_about = "Module for generating minimizing corpus using QEMU instrumentation"
)]
pub struct FuzzerOptions {
    #[arg(long, help = "Output directory")]
    output: String,

    #[arg(long, help = "Input directory")]
    input: String,

    #[arg(long, help = "Timeout in seconds", default_value_t = 1_u64)]
    timeout: u64,

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

pub fn fuzz() -> Result<(), Error> {
    let mut options = FuzzerOptions::parse();

    let corpus_dir = PathBuf::from(options.input);

    let files = corpus_dir
        .read_dir()
        .expect("Failed to read corpus dir")
        .map(|x| Ok(x?.path()))
        .collect::<Result<Vec<PathBuf>, io::Error>>()
        .expect("Failed to read dir entry");

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

    let mut shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    let monitor = SimpleMonitor::with_user_monitor(|s| {
        println!("{s}");
    });
    let (state, mut mgr) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider)
    {
        Ok(res) => res,
        Err(err) => match err {
            Error::ShuttingDown => {
                return Ok(());
            }
            _ => {
                panic!("Failed to setup the restarter: {err}");
            }
        },
    };

    let mut edges_shmem = shmem_provider.new_shmem(EDGES_MAP_DEFAULT_SIZE).unwrap();
    let edges = edges_shmem.as_slice_mut();
    unsafe { EDGES_MAP_PTR = edges.as_mut_ptr() };

    let mut edges_observer = unsafe {
        HitcountsMapObserver::new(ConstMapObserver::from_mut_ptr(
            "edges",
            NonNull::new(edges.as_mut_ptr())
                .expect("The edge map pointer is null.")
                .cast::<[u8; EDGES_MAP_DEFAULT_SIZE]>(),
        ))
    };

    let mut feedback = MaxMapFeedback::new(&edges_observer);

    #[allow(clippy::let_unit_value)]
    let mut objective = ();

    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            StdRand::new(),
            InMemoryOnDiskCorpus::new(PathBuf::from(options.output)).unwrap(),
            NopCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap()
    });

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut harness = |_emulator: &mut Emulator<_, _, _, _, _>, input: &BytesInput| {
        let target = input.target_bytes();
        let mut buf = target.as_slice();
        let mut len = buf.len();
        if len > MAX_INPUT_SIZE {
            buf = &buf[0..MAX_INPUT_SIZE];
            len = MAX_INPUT_SIZE;
        }
        let len = len as GuestReg;

        unsafe {
            qemu.write_mem(input_addr, buf).expect("qemu write failed.");

            qemu.write_reg(Regs::Pc, test_one_input_ptr).unwrap();
            qemu.write_reg(Regs::Sp, stack_ptr).unwrap();
            qemu.write_return_address(ret_addr).unwrap();
            qemu.write_function_argument(CallingConvention::Cdecl, 0, input_addr)
                .unwrap();
            qemu.write_function_argument(CallingConvention::Cdecl, 1, len)
                .unwrap();

            match qemu.run() {
                Ok(QemuExitReason::Breakpoint(_)) => {}
                Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(Signal::SigInterrupt))) => {
                    process::exit(0)
                }
                Err(QemuExitError::UnexpectedExit) => return ExitKind::Crash,
                _ => panic!("Unexpected QEMU exit."),
            }
        }

        ExitKind::Ok
    };

    let modules = tuple_list!(StdEdgeCoverageChildModule::builder()
        .const_map_observer(edges_observer.as_mut())
        .build()?);

    let emulator = Emulator::empty().qemu(qemu).modules(modules).build()?;

    let mut executor = QemuForkExecutor::new(
        emulator,
        &mut harness,
        tuple_list!(edges_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        shmem_provider,
        core::time::Duration::from_millis(5000),
    )?;

    println!("Importing {} seeds...", files.len());

    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &files)
            .unwrap_or_else(|_| {
                println!("Failed to load initial corpus");
                process::exit(0);
            });
        println!("Imported {} seeds from disk.", state.corpus().count());
    }

    let size = state.corpus().count();
    println!(
        "Removed {} duplicates from {} seeds",
        files.len() - size,
        files.len()
    );

    mgr.send_exiting()?;
    Ok(())
}
