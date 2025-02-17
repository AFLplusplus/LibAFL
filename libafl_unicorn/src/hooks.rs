use libafl_targets::{EDGES_MAP_DEFAULT_SIZE, EDGES_MAP_PTR};
use unicorn_engine::Unicorn;

fn coverage_hook(_emu: &mut unicorn_engine::Unicorn<()>, pc: u64, _: u32) {
    unsafe {
        let id = pc % EDGES_MAP_DEFAULT_SIZE as u64;

        let ptr = EDGES_MAP_PTR.add(id as usize);
        let val = ptr.read().wrapping_add(1);
        ptr.write(val);
    }
}

pub fn set_coverage_hook(emu: &mut Unicorn<()>) {
    emu.add_block_hook(0x0, !0x0_u64, coverage_hook).unwrap();
}
