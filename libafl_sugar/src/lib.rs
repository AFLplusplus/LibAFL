//! Sugar API to simplify the life of the naibe user of `LibAFL`

use typed_builder::TypedBuilder;

use core::time::Duration;

use libafl::{
    observers::{CmpObserver, Observer},
    inputs::{HasTargetBytes, BytesInput},
    executors::ExitKind,
    Error,
};
use libafl_targets::{
    CmpLogObserver, CMPLOG_MAP, EDGES_MAP, MAX_EDGES_NUM,
};

pub const DEFAULT_TIMEOUT_SECS: u64 = 1200;

#[derive(TypedBuilder)]
pub struct InMemoryBytesCoverageSugar<'a, H>
where
    H: FnMut(&[u8]),
{
    /// Laucher configuration (default is random)
    #[builder(default = None)]
    configuration: Option<String>,
    /// Timeout of the executor
    #[builder(default = None)]
    timeout: Option<u64>,
    /// Flag if use CmpLog
    #[builder(default = false)]
    use_cmplog: bool,
    #[builder(default = 1337_u16)]
    broker_port: u16,
    /// The list of cores to run on
    cores: &'a [usize],
    /// The `ip:port` address of another broker to connect our new broker to for multi-machine
    /// clusters.
    #[builder(default = None)]
    remote_broker_addr: Option<&'a str>,
    /// Bytes harness    
    harness: H,
}

impl<'a, H> InMemoryBytesCoverageSugar<'a, H>
where
    H: FnMut(&[u8]),
{
    pub fn run(&mut self) {
        let conf = self.configuration.take().unwrap_or_else(|| {
            "TODO".into()
        });
        
        let tiemout = Duration::from_secs(self.timeout.take().unwrap_or(DEFAULT_TIMEOUT_SECS));
        
        let harness = |input: &BytesInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();
            (self.harness)(buf);
            ExitKind::Ok
        };
    }
}
