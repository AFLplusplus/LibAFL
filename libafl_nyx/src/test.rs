use libafl::{bolts::shmem::StdShMemProvider, monitors::MultiMonitor};

#[test]
fn test_main() {
    let mon = MultiMonitor::new(|s| println!("{:?}", s));
    let shmem_provider = StdShMemProvider::new();
}
