//! Hooks for the unicorn emulator
use libafl_targets::{EDGES_MAP_DEFAULT_SIZE, EDGES_MAP_PTR};
use unicorn_engine::Unicorn;

/// Hook that is called for every basic block
fn coverage_hook<D>(_emu: &mut Unicorn<D>, pc: u64, _: u32) {
    unsafe {
        let id = pc % EDGES_MAP_DEFAULT_SIZE as u64;

        let ptr = EDGES_MAP_PTR.add(id as usize);
        let val = ptr.read().wrapping_add(1);
        ptr.write(val);
    }
}

/// Sets the `coverage_hook` for the emulator
pub fn set_coverage_hook<D>(emu: &mut Unicorn<D>) {
    emu.add_block_hook(0x0, !0x0_u64, coverage_hook).unwrap();
}
