//! An AFL++ compatible afl-qemu-trace alternative using LibAFL QEMU as a backend.

use std::{env, ffi::c_void};

use libafl::{
    executors::hooks::inprocess::GLOBAL_STATE,
    inputs::{BytesInput, ValueInput},
    observers::ConstBytesMap,
    state::NopState,
};
use libafl_bolts::tuples::tuple_list;
use libafl_qemu::{
    Emulator,
    command::NopCommand,
    elf::EasyElf,
    modules::{edges::StdEdgeCoverageClassicModule, utils::filters::HasAddressFilterTuple},
};
use libafl_targets::{__afl_map_size, EDGES_MAP_DEFAULT_SIZE, EDGES_MAP_PTR, Forkserver};
use tsl::{TSLForkserverHook, TSLModule};

mod env_config;
mod tsl;

/// The fuzzer main
pub fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    let mut fs = Forkserver::new(TSLForkserverHook::new());

    // Share afl map
    unsafe {
        fs.map_shared_memory();
    }

    // For now, we consider the map size to be constant
    unsafe {
        assert_eq!(EDGES_MAP_DEFAULT_SIZE, *&raw const __afl_map_size);
    }

    let mut const_map = unsafe { ConstBytesMap::<EDGES_MAP_DEFAULT_SIZE>::new(EDGES_MAP_PTR) };

    unsafe {
        println!("map addr: {:#x}", EDGES_MAP_PTR as u64);
    }

    let modules = tuple_list!(
        StdEdgeCoverageClassicModule::builder()
            .const_map(&mut const_map)
            .jit(false)
            .hitcounts(true)
            .build()
            .unwrap(),
        TSLModule::new(),
    );

    let mut emulator =
        Emulator::<NopCommand, _, _, _, BytesInput, NopState<BytesInput>, _>::empty()
            .qemu_parameters(&args)
            .modules(modules)
            .build()
            .unwrap();

    let mut state = NopState::<BytesInput>::new();

    unsafe {
        GLOBAL_STATE.state_ptr = &raw mut state as *mut c_void;
    }

    let qemu = emulator.qemu();

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(emulator.binary_path(), &mut elf_buffer).unwrap();

    let entry_point = env_config::AFL_ENTRYPOINT.unwrap_or_else(|| {
        elf.entry_point(emulator.load_addr())
            .expect("Could not find the default entr point")
    });

    qemu.set_breakpoint(entry_point);
    unsafe { qemu.run().unwrap() };
    qemu.remove_breakpoint(entry_point);

    emulator.first_exec(&mut state);

    // Now that the libs are loaded, build the intrumentation filter
    for region in emulator.mappings() {
        if let Some(path) = region.path() {
            if path.contains(emulator.binary_path()) {
                let range = region.start()..region.end();
                emulator
                    .modules_mut()
                    .modules_mut()
                    .allow_address_range_all(&range);
            }
        }
    }

    unsafe {
        emulator.run_target_crash_hooks_on_dying_signal();
    }

    let dummy_input = ValueInput::from(vec![]);
    emulator.pre_exec(&mut state, &dummy_input);

    unsafe {
        fs.start_forkserver().unwrap();
    }

    unsafe {
        qemu.run().unwrap();
    }

    // QEMU should exit by itself
    unreachable!();
}
