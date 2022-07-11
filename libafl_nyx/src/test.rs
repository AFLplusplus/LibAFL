use std::{ffi::OsString, path::PathBuf, str::FromStr};

use libafl::{bolts::shmem::StdShMemProvider, monitors::MultiMonitor};

use crate::executor::NyxHelper;

#[test]
fn test_nyxhelper() {
    let share_dir = PathBuf::from_str("/tmp/nyx_libxml2/").unwrap();
    let cpu_id = 0;
    let enable_snap_mode = true;
    let nyx_type = crate::executor::NyxProcessType::ALONE;
    let helper = NyxHelper::new(share_dir, cpu_id, enable_snap_mode, nyx_type);
}
