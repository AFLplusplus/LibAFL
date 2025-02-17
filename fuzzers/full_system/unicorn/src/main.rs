use std::{env, fs::File, io::Read, path::PathBuf, ptr::NonNull};

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{ExitKind, InProcessExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{havoc_mutations, scheduled::StdScheduledMutator},
    nonzero,
    observers::{ConstMapObserver, HitcountsMapObserver, TimeObserver},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
    AsSlice, AsSliceMut,
};
use libafl_targets::EDGES_MAP_DEFAULT_SIZE;
pub use libafl_targets::EDGES_MAP_PTR;
#[cfg(feature = "code_hook")]
use libafl_unicorn::helper::get_stack_pointer;
use libafl_unicorn::{
    emu::{debug_print, memory_dump},
    hooks::set_coverage_hook,
};
#[cfg(feature = "mem_hook")]
use unicorn_engine::{unicorn_const::MemType, HookType};
use unicorn_engine::{
    unicorn_const::{Arch, SECOND_SCALE},
    Mode, Permission, RegisterARM, RegisterARM64, RegisterX86, Unicorn,
};

pub const CODE_ADDRESS: u64 = 0x9000;
pub const CODE_SIZE: u64 = 0x1000;
pub const RETURN_ADDRESS: u64 = CODE_ADDRESS + CODE_SIZE - 0x8; // Such as that it works in 32 and 64
                                                                // bit

pub const DATA_ADDRESS: u64 = 0x8000;
pub const DATA_SIZE: u64 = 0x1000;
pub const MAX_INPUT_SIZE: usize = 0x100; //1048576; // 1MB

pub const STACK_ADDRESS: u64 = 0x7000;
pub const STACK_SIZE: u64 = 0x1000;

fn main() {
    env_logger::init();

    let args: Vec<_> = env::args().collect();
    let mut emu = false;
    if args.len() < 2 {
        log::debug!("Please specify the arcghitecture");
        return;
    }

    let arch = match args[1].as_str() {
        "arm" => Arch::ARM,
        "arm64" => Arch::ARM64,
        "x86" => Arch::X86,
        _ => {
            panic!("This arcghitecture is not supported")
        }
    };

    if args.len() >= 3 && args[2] == "emu" {
        emu = true;
    }
    fuzzer(emu, arch);
}

pub fn init_registers(emu: &mut Unicorn<()>, sp: u64) {
    match emu.get_arch() {
        Arch::ARM => {
            emu.reg_write(RegisterARM::SP, sp)
                .expect("Could not setup register");
        }
        Arch::ARM64 => {
            emu.reg_write(RegisterARM64::SP, sp)
                .expect("Could not setup register");
        }
        Arch::X86 => {
            emu.reg_write(RegisterX86::ESP, sp)
                .expect("Could not setup register");
        }
        _ => {}
    }
}

// emulating
fn fuzzer(should_emulate: bool, arch: Arch) {
    let mode = match arch {
        Arch::ARM => Mode::ARM,
        Arch::ARM64 => Mode::ARM926,
        Arch::X86 => Mode::MODE_64,
        _ => Mode::MODE_64,
    };

    let mut emu = Unicorn::new(arch, mode).unwrap();

    unicorn_map_and_load_code(
        &mut emu,
        CODE_ADDRESS,
        CODE_SIZE as usize,
        match arch {
            Arch::ARM => "bin/foo_arm.bin",
            Arch::ARM64 => "bin/foo_arm64.bin",
            Arch::X86 => "bin/foo_x86.bin",
            _ => "",
        },
    );

    // Map the data section in memory
    emu.mem_map(
        DATA_ADDRESS,
        DATA_SIZE as usize,
        Permission::WRITE | Permission::READ,
    )
    .unwrap();

    emu.mem_map(
        STACK_ADDRESS,
        STACK_SIZE as usize,
        Permission::WRITE | Permission::READ,
    )
    .unwrap();

    #[cfg(feature = "code_hook")]
    add_code_hook(&mut emu);

    #[cfg(feature = "mem_hook")]
    emu.add_mem_hook(
        HookType::MEM_READ
            | HookType::MEM_READ_INVALID
            | HookType::MEM_WRITE
            | HookType::MEM_WRITE_UNMAPPED,
        0x0,
        !0x0_u64,
        mem_callback,
    )
    .unwrap();

    let mut shmem = StdShMemProvider::new()
        .unwrap()
        .new_shmem(EDGES_MAP_DEFAULT_SIZE)
        .unwrap();

    let shmem_buf = shmem.as_slice_mut();
    unsafe {
        EDGES_MAP_PTR = shmem_buf.as_mut_ptr();
    }

    let edges_observer = unsafe {
        HitcountsMapObserver::new(ConstMapObserver::<_, EDGES_MAP_DEFAULT_SIZE>::from_mut_ptr(
            "edges",
            NonNull::new(shmem_buf.as_mut_ptr())
                .expect("The edge map pointer is null.")
                .cast::<[u8; EDGES_MAP_DEFAULT_SIZE]>(),
        ))
    };

    // Add the coverage hook
    set_coverage_hook(&mut emu);

    // Save context
    let context = emu.context_init().unwrap();

    let mut harness = |input: &BytesInput| {
        emu.context_restore(&context).unwrap();

        let target = input.target_bytes();
        let mut buf = target.as_slice();
        let len = buf.len();
        if len > MAX_INPUT_SIZE {
            buf = &buf[0..MAX_INPUT_SIZE];
        }

        // Load data in memory
        emu.mem_write(DATA_ADDRESS, buf).unwrap();

        init_registers(&mut emu, STACK_ADDRESS + STACK_SIZE - 0x8);

        // Store the return address
        match arch {
            Arch::ARM => emu.reg_write(RegisterARM::LR, RETURN_ADDRESS).unwrap(),
            Arch::ARM64 => emu.reg_write(RegisterARM64::LR, RETURN_ADDRESS).unwrap(),
            Arch::X86 => {
                let bytes = u64::to_le_bytes(RETURN_ADDRESS);

                // Store the return value in the stack
                emu.mem_write(STACK_SIZE + STACK_ADDRESS - 0x8, &bytes)
                    .unwrap();
            }
            _ => {}
        }

        let mut address = CODE_ADDRESS;
        if arch == Arch::ARM {
            address += 0x1; // We use thumb mode
        }

        let result = emu.emu_start(address, RETURN_ADDRESS, SECOND_SCALE, 0x10000);

        match result {
            Ok(_) => {
                let result_value = match arch {
                    Arch::ARM => emu.reg_read(RegisterARM::R0).unwrap(),
                    Arch::ARM64 => emu.reg_read(RegisterARM64::W0).unwrap(),
                    Arch::X86 => emu.reg_read(RegisterX86::EAX).unwrap(),
                    _ => 0,
                };
                if result_value == 0x6 {
                    log::debug!("Result found: 0x{result_value:x}");

                    return ExitKind::Crash;
                }
            }
            Err(err) => {
                log::error!("Error: {:?}", err);

                memory_dump(&emu, 2);
                debug_print(&emu, true);
            }
        }

        ExitKind::Ok
    };

    if should_emulate {
        log::info!("Starting emulation:");
        let mem_data: Vec<u8> = vec![0x50, 0x24, 0x36, 0x0];
        harness(&BytesInput::from(mem_data));
        log::info!("Done");
        return;
    }

    let monitor = MultiMonitor::new(|s| log::info!("{s}"));
    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(monitor);

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // Feedback to rate the interest of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        MaxMapFeedback::new(&edges_observer),
        // MaxMapFeedback::new(&signal_observer),
        TimeFeedback::new(&time_observer),
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

    // A minimization+queue policy to get test cases from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the executor");

    // Generator of printable bytearrays of max size 32
    let mut generator = RandBytesGenerator::new(nonzero!(4));

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}

fn unicorn_map_and_load_code(emu: &mut Unicorn<()>, address: u64, size: usize, path: &str) -> u64 {
    let mut f = File::open(path).expect("Could not open file");
    let mut buffer = Vec::new();

    // read the whole file
    f.read_to_end(&mut buffer).expect("Could not read file");

    // Define memory regions
    emu.mem_map(address, address as usize + size, Permission::EXEC)
        .expect("failed to map code page");

    // Write memory
    emu.mem_write(address, &buffer)
        .expect("failed to write instructions");
    buffer.len() as u64
}

#[cfg(feature = "code_hook")]
fn add_code_hook(emu: &mut Unicorn<()>) {
    emu.add_code_hook(0x0, !0x0_u64, |emu, pc, _| {
        let sp = get_stack_pointer(emu);
        log::debug!("[PC: 0x{pc:x}] Hook: SP 0x:{sp:x}");
    })
    .unwrap();
}

#[cfg(feature = "mem_hook")]
fn mem_callback(
    emu: &mut unicorn_engine::Unicorn<()>,
    mem: MemType,
    address: u64,
    size: usize,
    value: i64,
) -> bool {
    match mem {
        MemType::WRITE => log::debug!(
            "[PC: 0x{:x}] Memory is being WRITTEN at adress: {address:x} size: {size:} value: {value:}",
            emu.pc_read().unwrap()
        ),
        MemType::READ => log::debug!(
            "[PC: 0x{:x}] Memory is being READ at adress: {address:x} size: {size:}",
            emu.pc_read().unwrap()
        ),
        _ => log::debug!(
            "[PC: 0x{:x}] Memory access type: {mem:?} adress: {address:x} size: {size:} value: {value:}",
            emu.pc_read().unwrap()
        ),
    }

    true
}
