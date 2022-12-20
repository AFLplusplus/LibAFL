use std::{
    ffi::CString,
    fs::File,
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    os::fd::{FromRawFd, RawFd},
};

use goblin::elf::Elf;
use libafl::{
    bolts::{current_nanos, AsSlice},
    corpus::{Corpus, InMemoryCorpus},
    events::SimpleEventManager,
    executors::{ExitKind, InProcessForkExecutor},
    feedback_or,
    feedbacks::{MaxMapFeedback, TimeFeedback},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    mutators::StdScheduledMutator,
    prelude::{
        havoc_mutations, tuple_list, ShMemProvider, StdRand, StdShMemProvider, TimeObserver,
    },
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, StdWeightedScheduler,
    },
    stages::{CalibrationStage, StdPowerMutationalStage},
    state::{HasCorpus, HasMaxSize, StdState},
    Error, Fuzzer, StdFuzzer,
};
use libafl_verilator::VerilatorMapObserver;
use nix::{fcntl::OFlag, sys::stat::Mode};

const BASE_EXECUTABLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/base-executable"));

mod wrapper {
    #![allow(non_snake_case)]
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(unused)]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use wrapper::*;

const MAX_CYCLES: usize = 1 << 14;

fn create_input_file() -> Result<(RawFd, File), Error> {
    let input_fd = nix::fcntl::open(
        "/tmp",
        OFlag::O_TMPFILE | OFlag::O_RDWR | OFlag::O_EXCL,
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

fn main() -> Result<(), Error> {
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
    unsafe {
        __libafl_ariane_start(input_filename.as_ptr());
    }
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
    'pumploop: loop {
        loop {
            match reader.read_line(&mut line) {
                Err(e) if e.kind() != ErrorKind::WouldBlock => {
                    panic!("Illegal error encountered while processing: {}", e);
                }
                Ok(_) => {
                    // in usermode: c.nop or nop, might change by compiler
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

    let mut mgr = SimpleEventManager::printing();

    let cov_observer = VerilatorMapObserver::new("verilated-edges".to_string(), true);

    let time_observer = TimeObserver::new("time");

    let cov_feedback = MaxMapFeedback::new_tracking(&cov_observer, true, false);

    let calibration = CalibrationStage::new(&cov_feedback);

    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        cov_feedback,
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new_with_observer(&time_observer)
    );

    let mut objective = (); // no feedback at this time :(

    let mut state = StdState::new(
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
    )?;
    state.set_max_size(1 << 11); // see cva6-base.c for details

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
        'pumploop: for _ in 0..MAX_CYCLES {
            loop {
                match reader.read_line(&mut line) {
                    Err(e) if e.kind() != ErrorKind::WouldBlock => {
                        panic!("Encountered IO error while processing: {}", e);
                    }
                    Ok(_) => {
                        let trimmed = line.trim();
                        let mut split = trimmed.split_ascii_whitespace().skip(1);
                        if let Some(pc) = split.next().and_then(|pc| pc.strip_prefix("0x")) {
                            let pc = usize::from_str_radix(pc, 16).unwrap();

                            if pc > target_address as usize
                                && pc < (target_address as usize + actual.len())
                            {
                                entered_execution_zone = true;
                                in_execution_zone = true;
                            } else if entered_execution_zone {
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
        state.generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 4)?;
        println!("Generated {} initial inputs", state.corpus().count());
    }

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

    Ok(())
}
