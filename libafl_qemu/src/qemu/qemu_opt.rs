use core::{
    fmt,
    fmt::{Display, Formatter},
};
use std::path::PathBuf;

use libafl_derive;
use strum_macros;
use typed_builder::TypedBuilder;

use crate::{Qemu, QemuInitError};

#[allow(non_camel_case_types)]
#[derive(Debug, strum_macros::Display, Clone)]
#[strum(prefix = "-accel ")]
pub enum Accelerator {
    kvm,
    tcg,
}

#[allow(non_camel_case_types)]
#[derive(Debug, strum_macros::Display, Clone)]
#[strum(prefix = "if=")]
pub enum DriveInterface {
    floppy,
    ide,
    mtd,
    none,
    pflash,
    scsi,
    sd,
    virtio,
}

#[allow(non_camel_case_types)]
#[derive(Debug, strum_macros::Display, Clone)]
#[strum(prefix = "format=")]
pub enum DiskImageFileFormat {
    qcow2,
    raw,
}

#[derive(Debug, Clone, Default, TypedBuilder)]
pub struct Drive {
    #[builder(default, setter(strip_option))]
    file: Option<PathBuf>,
    #[builder(default, setter(strip_option))]
    format: Option<DiskImageFileFormat>,
    #[builder(default, setter(strip_option))]
    interface: Option<DriveInterface>,
}

impl Display for Drive {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "-drive")?;

        let mut is_first_option = true;
        let mut separator = || {
            if is_first_option {
                is_first_option = false;
                " "
            } else {
                ","
            }
        };

        if let Some(file) = &self.file {
            write!(f, "{}file={}", separator(), file.to_str().unwrap())?;
        }
        if let Some(format) = &self.format {
            write!(f, "{}{format}", separator())?;
        }
        if let Some(interface) = &self.interface {
            write!(f, "{}{interface}", separator())?;
        }

        Ok(())
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, strum_macros::Display, Clone)]
#[strum(prefix = "-serial ")]
pub enum Serial {
    none,
    null,
    stdio,
}

#[allow(non_camel_case_types)]
#[derive(Debug, strum_macros::Display, Clone)]
#[strum(prefix = "-monitor ")]
pub enum Monitor {
    none,
    null,
    stdio,
}

/// Set the directory for the BIOS, VGA BIOS and keymaps.
#[derive(Debug, Clone)]
pub struct Bios {
    pub path: Option<PathBuf>,
}

impl Display for Bios {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(path) = &self.path {
            write!(f, "-L {}", path.to_str().unwrap())?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Kernel {
    pub path: PathBuf,
}

impl Display for Kernel {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "-kernel {}", self.path.to_str().unwrap())
    }
}

#[derive(Debug, Clone)]
pub struct LoadVM {
    pub path: PathBuf,
}

impl Display for LoadVM {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "-loadvm {}", self.path.to_str().unwrap())
    }
}

#[derive(Debug, Clone)]
pub struct Machine {
    pub machine: String,
}

impl Display for Machine {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "-machine {}", self.machine)
    }
}

#[derive(Debug, Clone, strum_macros::Display)]
pub enum Snapshot {
    #[strum(serialize = "-snapshot")]
    ENABLE,
    #[strum(serialize = "")]
    DISABLE,
}

#[derive(Debug, Clone, strum_macros::Display)]
pub enum StartCPU {
    #[strum(serialize = "")]
    ENABLE,
    #[strum(serialize = "-S")]
    DISABLE,
}

#[derive(Debug, Clone, strum_macros::Display)]
pub enum NoGraphic {
    #[strum(serialize = "-nographic")]
    ENABLE,
    #[strum(serialize = "")]
    DISABLE,
}

#[derive(Debug, Clone)]
pub enum RamSize {
    MB(u32),
    GB(u32),
}

impl Display for RamSize {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            RamSize::MB(mb) => write!(f, "-m {mb}M"),
            RamSize::GB(gb) => write!(f, "-m {gb}G"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SmpCpus {
    pub cpus: u32,
}

impl Display for SmpCpus {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "-smp {}", self.cpus)
    }
}

#[derive(Debug, Clone, strum_macros::Display)]
pub enum VgaPci {
    #[strum(serialize = "-device VGA")]
    ENABLE,
    #[strum(serialize = "")]
    DISABLE,
}

#[derive(Debug, Clone, Default, libafl_derive::Display, TypedBuilder)]
#[builder(build_method(into), builder_method(vis = "pub(crate)"))]
pub struct QemuConfig {
    #[builder(default, setter(strip_option))]
    accelerator: Option<Accelerator>,
    #[builder(default, setter(strip_option))]
    bios: Option<Bios>,
    #[builder(default)]
    drives: Vec<Drive>,
    #[builder(default, setter(strip_option))]
    kernel: Option<Kernel>,
    #[builder(default, setter(strip_option))]
    load_vm: Option<LoadVM>,
    #[builder(default, setter(strip_option))]
    machine: Option<Machine>,
    #[builder(default, setter(strip_option))]
    monitor: Option<Monitor>,
    #[builder(default, setter(strip_option))]
    no_graphic: Option<NoGraphic>,
    #[builder(default, setter(strip_option))]
    ram_size: Option<RamSize>,
    #[builder(default, setter(strip_option))]
    serial: Option<Serial>,
    #[builder(default, setter(strip_option))]
    smp_cpus: Option<SmpCpus>,
    #[builder(default, setter(strip_option))]
    snapshot: Option<Snapshot>,
    #[builder(default, setter(strip_option))]
    vga_pci: Option<VgaPci>,
    #[builder(default, setter(strip_option))]
    start_cpu: Option<StartCPU>,
}

impl Into<Result<Qemu, QemuInitError>> for QemuConfig {
    fn into(self) -> Result<Qemu, QemuInitError> {
        // TODO improve this without splitting
        let args = self
            .to_string()
            .split(' ')
            .map(std::string::ToString::to_string)
            .collect::<Vec<String>>();
        Qemu::init(&args, &[])
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn default_fmt_is_empty() {
        let opt: QemuConfig = QemuConfig::builder().build();
        assert_eq!(opt.to_string(), "");
    }

    #[test]
    fn drive_no_file_fmt() {
        let drive = Drive::builder()
            .format(DiskImageFileFormat::raw)
            .interface(DriveInterface::ide)
            .build();
        assert_eq!(drive.to_string(), "-drive format=raw,if=ide");
    }

    #[test]
    fn fuzzer_qemu_systemmode_config() {
        let shell_config = " \
            -machine mps2-an385 \
            -monitor null \
            -kernel ${TARGET_DIR}/example.elf \
            -serial null \
            -nographic \
            -snapshot \
            -drive file=${TARGET_DIR}/dummy.qcow2,format=qcow2,if=none \
            -S";
        let shell_config_args = str_split_sort(shell_config, " -");

        let qemu_opt: QemuConfig = Qemu::builder()
            .machine(Machine {
                machine: "mps2-an385".to_string(),
            })
            .monitor(Monitor::null)
            .kernel(Kernel {
                path: PathBuf::from("${TARGET_DIR}/example.elf"),
            })
            .serial(Serial::null)
            .no_graphic(NoGraphic::ENABLE)
            .snapshot(Snapshot::ENABLE)
            .drives(vec![Drive::builder()
                .interface(DriveInterface::none)
                .format(DiskImageFileFormat::qcow2)
                .file(PathBuf::from("${TARGET_DIR}/dummy.qcow2"))
                .build()])
            .start_cpu(StartCPU::DISABLE)
            .build();
        let qemu_opt_str = qemu_opt.to_string();
        let qemu_opt_str_args = str_split_sort(&qemu_opt_str, " -");

        assert_eq!(qemu_opt_str_args, shell_config_args);
    }

    #[test]
    fn accelerator_fmt() {
        let opt: QemuConfig = Qemu::builder().accelerator(Accelerator::kvm).build();
        assert_eq!(opt.to_string(), " -accel kvm");
    }

    #[must_use]
    fn str_split_sort<'a>(s: &'a str, separator: &str) -> Vec<&'a str> {
        let mut v = s.split(separator).collect::<Vec<&str>>();
        v.sort_unstable();
        v
    }
}
