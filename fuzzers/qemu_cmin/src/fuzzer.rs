//! A libfuzzer-like fuzzer using qemu for binary-only coverage
//!
#[cfg(feature = "i386")]
use core::mem::size_of;
use std::{env, io, path::PathBuf, process};

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
    current_nanos,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
    AsMutSlice, AsSlice,
};
use libafl_qemu::{
    edges::{QemuEdgeCoverageChildHelper, EDGES_MAP_PTR, EDGES_MAP_SIZE},
    elf::EasyElf,
    emu::Emulator,
    ArchExtras, CallingConvention, GuestAddr, GuestReg, MmapPerms, QemuForkExecutor, QemuHooks,
    Regs,
};

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
    name = format!("qemu_cmin-{}",env!("CPU_TARGET")),
    version = Version::default(),
    about,
    long_about = "Tool for generating minimizing corpus using QEMU instrumentation"
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
    let env: Vec<(String, String)> = env::vars().collect();
    let emu = Emulator::new(&options.args, &env).unwrap();

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buffer).unwrap();

    let test_one_input_ptr = elf
        .resolve_symbol("LLVMFuzzerTestOneInput", emu.load_addr())
        .expect("Symbol LLVMFuzzerTestOneInput not found");
    log::debug!("LLVMFuzzerTestOneInput @ {test_one_input_ptr:#x}");

    emu.entry_break(test_one_input_ptr);

    let pc: GuestReg = emu.read_reg(Regs::Pc).unwrap();
    log::debug!("Break at {pc:#x}");

    let ret_addr: GuestAddr = emu.read_return_address().unwrap();
    log::debug!("Return address = {ret_addr:#x}");
    emu.set_breakpoint(ret_addr);

    let input_addr = emu
        .map_private(0, MAX_INPUT_SIZE, MmapPerms::ReadWrite)
        .unwrap();
    log::debug!("Placing input at {input_addr:#x}");

    let stack_ptr: GuestAddr = emu.read_reg(Regs::Sp).unwrap();

    let mut shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    let monitor = SimpleMonitor::with_user_monitor(
        |s| {
            println!("{s}");
        },
        true,
    );
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

    let mut edges_shmem = shmem_provider.new_shmem(EDGES_MAP_SIZE).unwrap();
    let edges = edges_shmem.as_mut_slice();
    unsafe { EDGES_MAP_PTR = edges.as_mut_ptr() };

    let edges_observer = unsafe {
        HitcountsMapObserver::new(ConstMapObserver::<_, EDGES_MAP_SIZE>::from_mut_ptr(
            "edges",
            edges.as_mut_ptr(),
        ))
    };

    let mut feedback = MaxMapFeedback::tracking(&edges_observer, true, false);

    #[allow(clippy::let_unit_value)]
    let mut objective = ();

    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            StdRand::with_seed(current_nanos()),
            InMemoryOnDiskCorpus::new(PathBuf::from(options.output)).unwrap(),
            NopCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap()
    });

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let mut buf = target.as_slice();
        let mut len = buf.len();
        if len > MAX_INPUT_SIZE {
            buf = &buf[0..MAX_INPUT_SIZE];
            len = MAX_INPUT_SIZE;
        }
        let len = len as GuestReg;

        unsafe {
            emu.write_mem(input_addr, buf);
            emu.write_reg(Regs::Pc, test_one_input_ptr).unwrap();
            emu.write_reg(Regs::Sp, stack_ptr).unwrap();
            emu.write_return_address(ret_addr).unwrap();
            emu.write_function_argument(CallingConvention::Cdecl, 0, input_addr)
                .unwrap();
            emu.write_function_argument(CallingConvention::Cdecl, 1, len)
                .unwrap();
            emu.run();
        }

        ExitKind::Ok
    };

    let mut hooks = QemuHooks::new(
        emu.clone(),
        tuple_list!(QemuEdgeCoverageChildHelper::default(),),
    );

    let mut executor = QemuForkExecutor::new(
        &mut hooks,
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
