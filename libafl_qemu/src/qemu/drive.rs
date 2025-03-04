use std::io;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use libafl_bolts::core_affinity::CoreId;

pub enum QemuDiskKind {
    Qcow2,
    Raw,
}

pub struct MulticoreDrive {
    input: PathBuf,
    output_dir: PathBuf,
    kind: QemuDiskKind,
}

impl MulticoreDrive {
    pub fn new(input: PathBuf, output_dir: PathBuf) -> Self {
        let kind = if let Some(ext) = input.extension() {
            if ext.to_str().unwrap() == "qcow2" {
                QemuDiskKind::Qcow2
            } else {
                QemuDiskKind::Raw
            }
        } else {
            QemuDiskKind::Raw
        };

        Self {
            input,
            output_dir,
            kind,
        }
    }

    pub fn push(&mut self, core_id: &CoreId) -> Result<PathBuf, io::Error> {
        let input_fmt = match &self.kind {
            QemuDiskKind::Qcow2 => {
                "qcow2"
            }
            QemuDiskKind::Raw => {
                "raw"
            }
        };

        if !self.input.exists() {
            return Err(io::Error::new(ErrorKind::NotFound, "The input file does not exist."))
        }

        let input_fname = self.input.file_name().unwrap();
        let output_partial_path = self.output_dir.join(input_fname.to_str().unwrap());
        let output_f = PathBuf::from(format!("{}.{}", output_partial_path.display(), core_id.0));

        let backing = format!("backing_file={}", self.input.display());

        // qemu-img create -f qcow2 -o backing_file={{ LINUX_BUILDER_OUT }}/OVMF_VARS.4m.fd -F raw {{ LINUX_BUILDER_OUT }}/OVMF_VARS.4m.qcow2
        let mut qemu_img = Command::new("qemu-img");
        qemu_img.arg("create")
            .args(["-f", "qcow2"])
            .args(["-o", backing.as_str()])
            .args(["-F", input_fmt])
            .arg(&output_f);

        let mut res = qemu_img.spawn()?;

        let ret = res.wait()?;

        if ret == ExitStatus::default() {
            Ok(output_f)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "qemu-img failed."))
        }
    }
}