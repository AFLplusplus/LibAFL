use std::{env, fmt::Write, ops::Range};

use clap::{Parser, builder::Str};
use libafl_bolts::{Error, tuples::tuple_list};
use libafl_qemu::{
    Emulator, GuestAddr, NopEmulatorDriver, NopSnapshotManager, QemuExitError, QemuInitError,
    command::NopCommandManager,
    elf::EasyElf,
    modules::{AsanGuestModule, AsanModule, EmulatorModuleTuple, utils::filters::StdAddressFilter},
};
use log::{error, info};
use thiserror::Error;

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
            // Note that write!-ing into a String can never fail, despite the return type of write! being std::fmt::Result, so it can be safely ignored or unwrapped.
            // See https://rust-lang.github.io/rust-clippy/master/index.html#/format_collect
            let _ = writeln!(output, "{k:25}: {v}");
            output
        });

        format!("\n{version:}").into()
    }
}

#[readonly::make]
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[command(
    name = format!("runner-{}",env!("CPU_TARGET")),
    version = Version::default(),
    about,
    long_about = "Binary fuzzer using QEMU binary instrumentation"
)]
pub struct FuzzerOptions {
    #[clap(short, long, help = "Enable host asan")]
    pub asan: bool,

    #[clap(short, long, help = "Enable guest asan", conflicts_with = "asan")]
    pub gasan: bool,

    #[clap(short, long, help = "Enable output from the fuzzer clients")]
    pub verbose: bool,

    #[arg(long = "include-asan", help="Include asan address ranges", value_parser = FuzzerOptions::parse_ranges)]
    pub include_asan: Option<Vec<Range<GuestAddr>>>,

    #[arg(long = "exclude-asan", help="Exclude asan address ranges", value_parser = FuzzerOptions::parse_ranges, conflicts_with="include_asan")]
    pub exclude_asan: Option<Vec<Range<GuestAddr>>>,

    #[arg(last = true, help = "Arguments passed to the target")]
    pub args: Vec<String>,
}

impl FuzzerOptions {
    fn parse_ranges(src: &str) -> Result<Range<GuestAddr>, Error> {
        let parts = src.split('-').collect::<Vec<&str>>();
        if parts.len() == 2 {
            let start =
                GuestAddr::from_str_radix(parts[0].trim_start_matches("0x"), 16).map_err(|e| {
                    Error::illegal_argument(format!("Invalid start address: {} ({e:})", parts[0]))
                })?;
            let end =
                GuestAddr::from_str_radix(parts[1].trim_start_matches("0x"), 16).map_err(|e| {
                    Error::illegal_argument(format!("Invalid end address: {} ({e:})", parts[1]))
                })?;
            Ok(Range { start, end })
        } else {
            Err(Error::illegal_argument(format!(
                "Invalid range provided: {src:}"
            )))
        }
    }
}

pub fn fuzz() {
    env_logger::init();
    let mut options = FuzzerOptions::parse();

    let program = env::args().next().unwrap();
    info!("Program: {program:}");

    options.args.insert(0, program);
    info!("ARGS: {:#?}", options.args);

    let env = env::vars()
        .filter(|(k, _v)| k != "LD_LIBRARY_PATH")
        .collect::<Vec<(String, String)>>();

    let asan_filter = if let Some(include_asan) = &options.include_asan {
        info!("ASAN includes: {include_asan:#x?}");
        StdAddressFilter::allow_list(include_asan.to_vec())
    } else if let Some(exclude_asan) = &options.exclude_asan {
        info!("ASAN excludes: {exclude_asan:#x?}");
        StdAddressFilter::deny_list(exclude_asan.to_vec())
    } else {
        info!("ASAN no additional filter");
        StdAddressFilter::default()
    };

    let ret = if options.asan {
        info!("Enabling ASAN");
        let modules = tuple_list!(AsanModule::builder().env(&env).filter(asan_filter).build());
        info!("Modules: {:#?}", modules);
        run(options, modules)
    } else if options.gasan {
        info!("Enabling Guest ASAN");
        let modules = tuple_list!(AsanGuestModule::new(&env, asan_filter));
        info!("Modules: {:#?}", modules);
        run(options, modules)
    } else {
        info!("Running without ASAN");
        let modules = tuple_list!();
        info!("Modules: {:#?}", modules);
        run(options, modules)
    };
    match ret {
        Ok(r) => {
            info!("Exit: {r:?}");
        }
        Err(e) => {
            error!("Error: {e:?}");
        }
    }
}

fn run<M: EmulatorModuleTuple<(), ()>>(
    options: FuzzerOptions,
    modules: M,
) -> Result<(), LauncherError> {
    info!("Building emulator");
    let mut emulator: Emulator<
        (),
        NopCommandManager,
        NopEmulatorDriver,
        M,
        (),
        (),
        NopSnapshotManager,
    > = Emulator::empty()
        .qemu_parameters(options.args)
        .modules(modules)
        .build()
        .map_err(LauncherError::Init)?;
    info!("Build emultor");
    let qemu = emulator.qemu();

    let mut elf_buffer = Vec::new();
    let elf =
        EasyElf::from_file(qemu.binary_path(), &mut elf_buffer).map_err(LauncherError::ElfError)?;

    let test_one_input = elf.resolve_symbol("LLVMFuzzerTestOneInput", qemu.load_addr());
    log::info!(
        "LLVMFuzzerTestOneInput @ {:#x}",
        test_one_input.unwrap_or_default()
    );
    let main = elf.resolve_symbol("main", qemu.load_addr());
    log::info!("main @ {:#x}", main.unwrap_or_default());

    let entry = test_one_input.or(main);
    log::info!("entry @ {:#x}", entry.unwrap_or_default());

    match entry {
        Some(e) => qemu.entry_break(e),
        None => Err(LauncherError::FailedToFindEntry)?,
    }

    let mut state = ();
    emulator.modules_mut().first_exec_all(qemu, &mut state);

    info!("Running emulator");
    unsafe { qemu.run().map_err(LauncherError::Exit)? };
    info!("Emulator exited");
    Ok(())
}

#[derive(Error, Debug)]
pub enum LauncherError {
    #[error("Qemu init error: {0:?}")]
    Init(QemuInitError),
    #[error("Qemu error: {0:?}")]
    Exit(QemuExitError),
    #[error("Elf error: {0:?}")]
    ElfError(Error),
    #[error("Failed to find entry point")]
    FailedToFindEntry,
}
