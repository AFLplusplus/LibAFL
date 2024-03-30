/// [`NyxHelper`] is used to wrap `NyxProcess`
use std::{fmt::Debug, path::Path};

use libafl::Error;
use libnyx::NyxProcess;

use crate::settings::NyxSettings;

pub struct NyxHelper {
    pub nyx_process: NyxProcess,

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
        let work_dir = share_dir.as_ref().join("workdir");
        let share_dir_str = share_dir.as_ref().to_str().ok_or(Error::illegal_argument(
            "`share_dir` contains invalid UTF-8",
        ))?;
        let work_dir_str = work_dir
            .to_str()
            .ok_or(Error::illegal_argument("`work_dir` contains invalid UTF-8"))?;

        let nyx_process_type = match settings.parent_cpu_id {
            None => NyxProcessType::ALONE,
            Some(parent_cpu_id) if settings.cpu_id == parent_cpu_id => NyxProcessType::PARENT,
            _ => NyxProcessType::CHILD,
        };
        let mut nyx_process = (match nyx_process_type {
            NyxProcessType::ALONE => NyxProcess::new(
                share_dir_str,
                work_dir_str,
                settings.cpu_id,
                settings.input_buffer_size,
                /* input_buffer_write_protection= */ true,
            ),
            NyxProcessType::PARENT => NyxProcess::new_parent(
                share_dir_str,
                work_dir_str,
                settings.cpu_id,
                settings.input_buffer_size,
                /* input_buffer_write_protection= */ true,
            ),
            NyxProcessType::CHILD => NyxProcess::new_child(
                share_dir_str,
                work_dir_str,
                settings.cpu_id,
                /* worker_id= */ settings.cpu_id,
            ),
        })
        .map_err(Error::illegal_argument)?;

        nyx_process.option_set_reload_mode(settings.snap_mode);
        nyx_process.option_set_timeout(settings.timeout_secs, settings.timeout_micro_secs);
        nyx_process.option_apply();

        let bitmap_size = nyx_process.bitmap_buffer_size();
        let bitmap_buffer = nyx_process.bitmap_buffer_mut().as_mut_ptr();

        Ok(Self {
            nyx_process,
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
