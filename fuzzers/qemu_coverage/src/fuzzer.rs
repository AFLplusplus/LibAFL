//! A libfuzzer-like fuzzer using qemu for binary-only coverage
//!
#[cfg(feature = "i386")]
use core::mem::size_of;
use core::time::Duration;
use std::{env, fs::DirEntry, io, path::PathBuf, process};

use clap::{builder::Str, Parser};
use libafl::{
    corpus::{Corpus, NopCorpus},
    events::{launcher::Launcher, EventConfig, EventRestarter},
    executors::{ExitKind, TimeoutExecutor},
    fuzzer::StdFuzzer,
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    prelude::LlmpRestartingEventManager,
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
    AsSlice,
};
use libafl_qemu::{
    drcov::QemuDrCovHelper, elf::EasyElf, emu::Emulator, MmapPerms, QemuExecutor, QemuHooks,
    QemuInstrumentationFilter, Regs,
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

pub fn fuzz() {
    let mut options = FuzzerOptions::parse();

    let corpus_dir = PathBuf::from(options.input);

    let corpus_files = corpus_dir
        .read_dir()
        .expect("Failed to read corpus dir")
        .collect::<Result<Vec<DirEntry>, io::Error>>()
        .expect("Failed to read dir entry");

    let num_files = corpus_files.len();
    let num_cores = options.cores.ids.len();
    let files_per_core = (num_files as f64 / num_cores as f64).ceil() as usize;

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

    let mut run_client = |state: Option<_>, mut mgr: LlmpRestartingEventManager<_, _>, core_id| {
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
                StdRand::with_seed(current_nanos()),
                NopCorpus::new(),
                NopCorpus::new(),
                &mut feedback,
                &mut objective,
            )
            .unwrap()
        });

        let scheduler = QueueScheduler::new();
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
            tuple_list!(QemuDrCovHelper::new(
                QemuInstrumentationFilter::None,
                rangemap,
                PathBuf::from(&options.coverage),
                false,
            )),
        );

        let executor = QemuExecutor::new(
            &mut hooks,
            &mut harness,
            (),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )
        .expect("Failed to create QemuExecutor");

        let mut executor = TimeoutExecutor::new(executor, Duration::from_secs(options.timeout));

        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs_by_filenames(&mut fuzzer, &mut executor, &mut mgr, &files)
                .unwrap_or_else(|_| {
                    println!("Failed to load initial corpus at {:?}", &corpus_dir);
                    process::exit(0);
                });
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        println!("Processed {} inputs from disk.", files.len());

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
