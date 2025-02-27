#![cfg(feature = "std")]
#![cfg(feature = "libipt")]
#![cfg(target_os = "linux")]

use core::arch::asm;
use std::process;

use libafl_intelpt::{Image, IntelPT, availability};
use nix::{
    sys::{
        signal::{Signal, kill, raise},
        wait::{WaitPidFlag, waitpid},
    },
    unistd::{ForkResult, fork},
};
use proc_maps::get_process_maps;

/// To run this test ensure that the executable has the required capabilities.
/// This can be achieved with the script `./run_integration_tests_linux_with_caps.sh`
#[test]
fn intel_pt_trace_fork() {
    if let Err(reason) = availability() {
        // Mark as `skipped` once this will be possible https://github.com/rust-lang/rust/issues/68007
        println!("Intel PT is not available, skipping test. Reasons:");
        println!("{reason}");
        return;
    }

    let pid = match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => child,
        Ok(ForkResult::Child) => {
            raise(Signal::SIGSTOP).expect("Failed to stop the process");
            // This will generate a sequence of tnt packets containing 255 taken branches
            unsafe {
                let mut count = 0;
                asm!(
                "2:",
                "add {0:r}, 1",
                "cmp {0:r}, 255",
                "jle 2b",
                inout(reg) count,
                options(nostack)
                );
                let _ = count;
            }
            process::exit(0);
        }
        Err(e) => panic!("Fork failed {e}"),
    };

    let pt_builder = IntelPT::builder().pid(Some(pid.as_raw()));
    let mut pt = pt_builder.build().expect("Failed to create IntelPT");
    pt.enable_tracing().expect("Failed to enable tracing");

    waitpid(pid, Some(WaitPidFlag::WUNTRACED)).expect("Failed to wait for the child process");
    let maps = get_process_maps(pid.into()).unwrap();
    kill(pid, Signal::SIGCONT).expect("Failed to continue the process");

    waitpid(pid, None).expect("Failed to wait for the child process");
    pt.disable_tracing().expect("Failed to disable tracing");

    let mut image = Image::new(Some("test_trace_pid")).unwrap();
    for map in maps {
        if map.is_exec() && map.filename().is_some() {
            match image.add_file(
                map.filename().unwrap().to_str().unwrap(),
                map.offset as u64,
                map.size() as u64,
                None,
                map.start() as u64,
            ) {
                Err(e) => println!("skipping mapping of {:?}: {:?}", map.filename().unwrap(), e),
                Ok(()) => println!(
                    "mapping for {:?} added successfully {:#x} - {:#x}",
                    map.filename().unwrap(),
                    map.start(),
                    map.start() + map.size()
                ),
            }
        }
    }

    let mut map = vec![0u16; 0x10_00];
    pt.decode_traces_into_map(&mut image, map.as_mut_ptr(), map.len())
        .unwrap();

    let assembly_jump_id = map.iter().position(|count| *count >= 254);
    assert!(
        assembly_jump_id.is_some(),
        "Assembly jumps not found in traces"
    );
}
