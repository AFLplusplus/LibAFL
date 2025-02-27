/// [`NyxHelper`] is used to wrap `NyxProcess`
use core::{fmt::Debug, time::Duration};
use std::{fs::File, path::Path};

use libafl::Error;
use libnyx::{NyxConfig, NyxProcess, NyxProcessRole};

use crate::settings::NyxSettings;

pub struct NyxHelper {
    pub nyx_process: NyxProcess,
    pub nyx_stdout: File,
    pub redqueen_path: String,

    pub timeout: Duration,

    pub bitmap_size: usize,
    pub bitmap_buffer: *mut u8,
}

#[derive(Clone, Copy, Debug)]
pub enum NyxProcessType {
    /// stand alone mode
    ALONE,
    /// parallel mode's parent, used to create snapshot
    PARENT,
    /// parallel mode's child, consume snapshot and execute
    CHILD,
}

impl NyxHelper {
    /// Create [`NyxProcess`] and do basic settings. It will convert the
    /// instance to a parent or child using `parent_cpu_id` when
    /// `parallel_mode` is set.
    pub fn new<P>(share_dir: P, settings: NyxSettings) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let share_dir_str = share_dir.as_ref().to_str().ok_or(Error::illegal_argument(
            "`share_dir` contains invalid UTF-8",
        ))?;

        let mut nyx_config = NyxConfig::load(share_dir_str).map_err(|e| {
            Error::illegal_argument(format!("Failed to load Nyx config from share dir: {e}"))
        })?;
        nyx_config.set_input_buffer_size(settings.input_buffer_size);
        nyx_config.set_process_role(match settings.parent_cpu_id {
            None => NyxProcessRole::StandAlone,
            Some(parent_cpu_id) if parent_cpu_id == settings.cpu_id => NyxProcessRole::Parent,
            _ => NyxProcessRole::Child,
        });
        nyx_config.set_worker_id(settings.cpu_id);

        let mut nyx_process = NyxProcess::new(&mut nyx_config, settings.cpu_id)
            .map_err(|e| Error::illegal_state(format!("Failed to create Nyx process: {e}")))?;
        nyx_process.option_set_reload_mode(settings.snap_mode);
        nyx_process.option_set_timeout(settings.timeout_secs, settings.timeout_micro_secs);
        nyx_process.option_apply();

        let path = Path::new(nyx_config.workdir_path())
            .join(format!("hprintf_{}", nyx_config.worker_id()));
        let nyx_stdout = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| Error::illegal_state(format!("Failed to create Nyx stdout file: {e}")))?;

        let bitmap_size = nyx_process.bitmap_buffer_size();
        let bitmap_buffer = nyx_process.bitmap_buffer_mut().as_mut_ptr();

        let mut timeout = Duration::from_secs(u64::from(settings.timeout_secs));
        timeout += Duration::from_micros(u64::from(settings.timeout_micro_secs));

        let redqueen_path = format!(
            "{}/redqueen_workdir_{}/redqueen_results.txt",
            nyx_config.workdir_path(),
            nyx_config.worker_id()
        );

        Ok(Self {
            nyx_process,
            nyx_stdout,
            redqueen_path,
            timeout,
            bitmap_size,
            bitmap_buffer,
        })
    }

    /// Set a timeout for Nyx.
    pub fn set_timeout(&mut self, secs: u8, micro_secs: u32) {
        self.nyx_process.option_set_timeout(secs, micro_secs);
        self.nyx_process.option_apply();
    }
}
