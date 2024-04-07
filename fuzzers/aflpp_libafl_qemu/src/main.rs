use libafl::prelude::*;
use libafl_bolts::prelude::*;
use libafl_qemu::{
    asan::{ QemuAsanHelper, QemuAsanOptions},
    cmplog::{CmpLogObserver, QemuCmpLogHelper, QemuCmpLogRoutinesHelper},
    calls::{QemuCallTracerHelper, FullBacktraceCollector},
    edges::{edges_map_mut_slice, std_edges_map_observer, QemuEdgeCoverageClassicHelper, QemuEdgeCoverageHelper, MAX_EDGES_NUM},
    elf::EasyElf,
    emu::Emulator,
    helper::{QemuFilterList, HasInstrumentationFilter, QemuHelper, QemuHelperTuple},
    hooks::QemuHooks,
    snapshot::QemuSnapshotHelper,
    QemuExecutor, Regs, SYS_close, SYS_faccessat, SYS_lseek, SYS_newfstatat, SYS_openat, SYS_read,
    SYS_rt_sigprocmask, SYS_write, SyscallHookResult,
};
use libafl_targets::forkserver::{ForkserverHooks, start_forkserver_with_hooks, map_shared_memory};
use std::env;
use nix::unistd::{close, pipe, read, write};
use nix::libc;

const TSL_FD: std::os::fd::RawFd = 196;

struct TSLHooks {
    read_end: std::os::fd::RawFd,
}

impl TSLHooks {
    fn new() -> Self {
        Self { read_end: 0 }
    }
    
    fn wait_tsl(&mut self) -> Result<(), ()> {
        Ok(())
    }
}

impl ForkserverHooks for TSLHooks {
    extern "C" fn pre_fork(&mut self) {
      // Establish a channel with child to grab translation commands.
      // We'll  read from the pipe read end, child will write to TSL_FD.
        let (read_end, write_end) = pipe().expect("Could not create TSL pipe");
        self.read_end = read_end;
        dup2(write_end, TSL_FD).expect("Could not dup2 the TSL pipe write end");
        close(write_end);
    }
    extern "C" fn post_fork(&mut self, pid: libc::pid_t) {
        if pid != 0 {
            // Parent
            close(TSL_FD);
        } else {
            // Child
            close(self.read_end);
        }
    }
    extern "C" fn iter_start(&mut self) {
        self.wait_tsl().expect("Wait for TSL failed");
    }
    extern "C" fn iter_end(&mut self, status: i32) {}
}

fn main() {
    let in_afl = env::var("__AFL_SHM_ID").is_ok();

    // Initialize QEMU
    let mut args: Vec<String> = env::args().collect();
    let mut env: Vec<(String, String)> = env::vars().collect();

    //let (emu, asan) = init_with_asan(&mut args, &mut env).unwrap();
    let emu = Emulator::new(&mut args, &mut env).unwrap();
    
    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buffer).unwrap();

    let entry_point = elf
        .entry_point(emu.load_addr())
        .expect("Entry point not found");
    
    // Break at the entry point after the loading process
    emu.set_breakpoint(entry_point);
    unsafe { emu.run() };
    emu.remove_breakpoint(entry_point);
    
    // Now that the libs are loaded, build the intrumentation filter
    let mut allow_list = vec![];
    for region in emu.mappings() {
        if let Some(path) = region.path() {
            if path.contains(emu.binary_path()) {
                allow_list.push(region.start()..region.end());
                // println!("Instrument {:?} {:#x}-{:#x}", path, region.start(), region.end());
            }
        }
    }
    
    if in_afl { map_shared_memory(); }
    
    let mut hooks = QemuHooks::reproducer(
            emu.clone(),
        tuple_list!(
           QemuEdgeCoverageClassicHelper::new(QemuFilterList::None)
        ),
    );
    
    let input = BytesInput::new(vec![]);
    
    let mut test_harness = |_: &BytesInput| {
        unsafe { emu.run() };
        ExitKind::Ok
    };

    if in_afl { start_forkserver(); }
    
    hooks.repro_run(&mut test_harness, &input);
}
