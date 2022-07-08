use libafl::{monitors::MultiMonitor, bolts::shmem::StdShMemProvider};

#[test]
fn test_main(){
   let mon = MultiMonitor::new(|s|println!("{:?}",s));
   let shmem_provider = StdShMemProvider::new();
   

}