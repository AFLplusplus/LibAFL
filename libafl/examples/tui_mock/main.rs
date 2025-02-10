//! An example for TUI that uses the TUI without any real data.
//! This is mainly to fix the UI without having to run a real fuzzer.

use std::{thread::sleep, time::Duration};

use libafl::{
    events::stats::{manager::ClientStatsManager, ClientStats},
    monitors::{tui::TuiMonitor, Monitor},
};
use libafl_bolts::ClientId;

pub fn main() {
    let mut monitor = TuiMonitor::builder().build();

    let _client_stats = ClientStats::default();
    let mut client_stats_manager = ClientStatsManager::default();

    monitor.display(&mut client_stats_manager, "Test", ClientId(0));
    sleep(Duration::from_secs(10));
}
