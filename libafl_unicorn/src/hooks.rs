pub use libafl_targets::{edges_max_num, EDGES_MAP, EDGES_MAP_PTR, EDGES_MAP_SIZE, MAX_EDGES_NUM};

static mut PREV_LOC: u64 = 0;

pub fn block_hook(_emu: &mut unicorn_engine::Unicorn<()>, address: u64, small: u32) {
    unsafe {
        let hash = (address ^ PREV_LOC) & (EDGES_MAP_SIZE as u64 - 1);
        //println!("Block hook: 0x{:X}\t size:{:#} hash: {:X}", address, small, hash);
        EDGES_MAP[hash as usize] += 1;
        PREV_LOC = address >> 1;
    }
}
