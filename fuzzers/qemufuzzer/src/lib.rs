#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use afl::corpus::InMemoryCorpus;
use afl::engines::Engine;
use afl::engines::Fuzzer;
use afl::engines::State;
use afl::engines::StdFuzzer;
use afl::events::{SimpleStats, LlmpEventManager};
use afl::executors::inmemory::InMemoryExecutor;
use afl::executors::{Executor, ExitKind};
use afl::feedbacks::MaxMapFeedback;
use afl::generators::RandPrintablesGenerator;
use afl::mutators::scheduled::HavocBytesMutator;
use afl::mutators::HasMaxSize;
use afl::observers::VariableMapObserver;
use afl::stages::mutational::StdMutationalStage;
use afl::tuples::tuple_list;
use afl::utils::StdRand;

use core::cmp::min;

mod regs;
use regs::*;

const FUZZ_MAP_SIZE: usize = 1048576;

type TargetULong = u64;

extern "C" {
    fn fuzz_run_target(regs: *const x86_64_regs);
    fn fuzz_write_mem(addr: TargetULong, buf: *const u8, size: usize);
    // fn fuzz_read_mem(addr: TargetULong, buf: *const u8, size: usize);

    static fuzz_start_regs: x86_64_regs;
    static mut fuzz_hitcounts_map: [u8; FUZZ_MAP_SIZE];
    static mut fuzz_edges_id: usize;
}

fn harness<I>(_executor: &dyn Executor<I>, buf: &[u8]) -> ExitKind {
    unsafe {
        let mut regs = fuzz_start_regs.clone();
        let len = min(buf.len(), 4096);
        regs.rsi = len as u64;
        fuzz_write_mem(regs.rdi, buf.as_ptr(), len);
        fuzz_run_target(&regs);
    }
    ExitKind::Ok
}

const NAME_COV_MAP: &str = "cov_map";

#[no_mangle]
pub extern "C" fn fuzz_main_loop() {
    let mut rand = StdRand::new(0);

    let mut corpus = InMemoryCorpus::new();
    let mut generator = RandPrintablesGenerator::new(32);

    let stats = SimpleStats::new(|s| println!("{}", s));
    let mut mgr = LlmpEventManager::new_on_port(1337, stats).unwrap();
    if mgr.is_broker() {
        println!("Doing broker things.");
        mgr.broker_loop().unwrap();
    }
    println!("We're a client, let's fuzz :)");

    let edges_observer = VariableMapObserver::new(&NAME_COV_MAP, unsafe { &mut fuzz_hitcounts_map }, unsafe { &fuzz_edges_id });
    let edges_feedback = MaxMapFeedback::new_with_observer(&NAME_COV_MAP, &edges_observer);

    let executor = InMemoryExecutor::new("QEMUFuzzer", harness, tuple_list!(edges_observer));
    let mut state = State::new(tuple_list!(edges_feedback));

    let mut engine = Engine::new(executor);

    state
        .generate_initial_inputs(
            &mut rand,
            &mut corpus,
            &mut generator,
            &mut engine,
            &mut mgr,
            4,
        )
        .expect("Failed to load initial inputs");

    let mut mutator = HavocBytesMutator::new_default();
    mutator.set_max_size(4096);

    let stage = StdMutationalStage::new(mutator);
    let mut fuzzer = StdFuzzer::new(tuple_list!(stage));

    fuzzer
        .fuzz_loop(&mut rand, &mut state, &mut corpus, &mut engine, &mut mgr)
        .expect("Fuzzer fatal error");
    #[cfg(feature = "std")]
    println!("OK");
}
