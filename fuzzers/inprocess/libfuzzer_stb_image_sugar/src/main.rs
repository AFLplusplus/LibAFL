//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for `stb_image`.
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use std::{env, path::PathBuf};

use libafl_bolts::core_affinity::Cores;
use libafl_sugar::InMemoryBytesCoverageSugar;
use libafl_targets::{libfuzzer_initialize, libfuzzer_test_one_input};

pub fn main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    // unsafe { RegistryBuilder::register::<Tokens>(); }

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );
    fuzz(
        &[PathBuf::from("./corpus")],
        PathBuf::from("./output"),
        &Cores::all().unwrap(),
        1337,
    );
}

/// The actual fuzzer
fn fuzz(input_dirs: &[PathBuf], output_dir: PathBuf, cores: &Cores, broker_port: u16) {
    // Call LLVMFUzzerInitialize() if present.
    let args: Vec<String> = env::args().collect();
    if unsafe { libfuzzer_initialize(&args) } == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1");
    }

    InMemoryBytesCoverageSugar::builder()
        .input_dirs(input_dirs)
        .output_dir(output_dir)
        .cores(cores)
        .broker_port(broker_port)
        .harness(|buf| unsafe {
            libfuzzer_test_one_input(buf);
        })
        .build()
        .run();
}
