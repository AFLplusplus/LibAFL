#![feature(link_llvm_intrinsics)]

extern {
    #[link_name = "llvm.readcyclecounter"]
    pub fn readcyclecounter() -> u64;
}
