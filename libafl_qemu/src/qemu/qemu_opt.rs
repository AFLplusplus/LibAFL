use core::fmt;
use std::{fmt::Formatter, path::PathBuf};

use strum_macros::Display;

#[allow(non_camel_case_types)]
#[derive(Default, Debug, Display, Clone, Copy)]
pub enum QemuOptAccelerator {
    kvm,
    #[default]
    tcg,
}

#[allow(non_camel_case_types)]
#[derive(Default, Debug, Display, Clone, Copy)]
pub enum QemuOptDriveInterface {
    floppy,
    #[default]
    ide,
    mtd,
    none,
    pflash,
    scsi,
    sd,
    virtio,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Display, Clone, Copy)]
pub enum QemuOptDiskImageFileFormat {
    qcow2,
    raw,
}

#[derive(Debug, Default, Clone)]
pub struct QemuOptDrive {
    file: Option<PathBuf>,
    format: Option<QemuOptDiskImageFileFormat>,
    interface: Option<QemuOptDriveInterface>,
}

impl fmt::Display for QemuOptDrive {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, " -drive")?;

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
            write!(f, "{}format={}", separator(), format)?;
        }
        if let Some(interface) = &self.interface {
            write!(f, "{}if={}", separator(), interface)?;
        }

        Ok(())
    }
}

#[allow(non_camel_case_types)]
#[derive(Default, Debug, Display, Clone, Copy)]
pub enum QemuOptSerial {
    none,
    null,
    #[default]
    stdio,
}

#[derive(Debug, Default, Clone)]
pub struct QemuOpt {
    accelerator: Option<QemuOptAccelerator>,
    /// Set the directory for the BIOS, VGA BIOS and keymaps.
    bios_path: Option<PathBuf>,
    drives: Vec<QemuOptDrive>,
    kernel: Option<PathBuf>,
    load_vm: Option<PathBuf>,
    machine: Option<String>,
    monitor: Option<QemuOptSerial>,
    no_graphic: bool,
    /// ram size in MiB
    ram_size: Option<u32>,
    serial: Option<QemuOptSerial>,
    smp_cpus: Option<u32>,
    snapshot: bool,
    vga_pci: bool,
    do_not_start_cpu: bool,
}

impl fmt::Display for QemuOpt {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(accelerator) = &self.accelerator {
            write!(f, " -accel {accelerator}")?;
        }

        if let Some(bios_path) = &self.bios_path {
            write!(f, " -L {}", bios_path.to_str().unwrap())?;
        }

        for drive in &self.drives {
            drive.fmt(f)?;
        }

        if let Some(kernel) = &self.kernel {
            write!(f, " -kernel {}", kernel.to_str().unwrap())?;
        }

        if let Some(load_vm) = &self.load_vm {
            write!(f, " -loadvm {}", load_vm.to_str().unwrap())?;
        }

        if let Some(machine) = &self.machine {
            write!(f, " -machine {machine}")?;
        }

        if let Some(monitor) = &self.monitor {
            write!(f, " -monitor {monitor}")?;
        }

        if self.no_graphic {
            write!(f, " -nographic")?;
        }

        if let Some(ram_size) = &self.ram_size {
            write!(f, " -m {ram_size}M")?;
        }

        if let Some(serial) = &self.serial {
            write!(f, " -serial {serial}")?;
        }

        if let Some(smp_cpus) = &self.smp_cpus {
            write!(f, " -smp {smp_cpus}")?;
        }

        if self.snapshot {
            write!(f, " -snapshot")?;
        }

        if self.vga_pci {
            write!(f, " -device VGA")?;
        }

        if self.do_not_start_cpu {
            write!(f, " -S")?;
        }

        Ok(())
    }
}

impl QemuOptDrive {
    #[must_use]
    pub fn new() -> QemuOptDrive {
        QemuOptDrive::default()
    }

    #[must_use]
    pub fn file(mut self, file: PathBuf) -> QemuOptDrive {
        self.file = Some(file);
        self
    }

    #[must_use]
    pub fn format(mut self, format: QemuOptDiskImageFileFormat) -> QemuOptDrive {
        self.format = Some(format);
        self
    }

    #[must_use]
    pub fn interface(mut self, interface: QemuOptDriveInterface) -> QemuOptDrive {
        self.interface = Some(interface);
        self
    }
}

impl QemuOpt {
    #[must_use]
    pub fn new() -> QemuOpt {
        QemuOpt::default()
    }

    #[must_use]
    pub fn accelerator(mut self, accelerator: QemuOptAccelerator) -> QemuOpt {
        self.accelerator = Some(accelerator);
        self
    }

    #[must_use]
    pub fn bios_path(mut self, bios_path: PathBuf) -> QemuOpt {
        self.bios_path = Some(bios_path);
        self
    }

    #[must_use]
    pub fn add_drive(mut self, drive: QemuOptDrive) -> QemuOpt {
        self.drives.push(drive);
        self
    }

    #[must_use]
    pub fn kernel(mut self, kernel: PathBuf) -> QemuOpt {
        self.kernel = Some(kernel);
        self
    }

    #[must_use]
    pub fn load_vm(mut self, load_vm: PathBuf) -> QemuOpt {
        self.load_vm = Some(load_vm);
        self
    }

    #[must_use]
    pub fn machine(mut self, machine: String) -> QemuOpt {
        self.machine = Some(machine);
        self
    }

    #[must_use]
    pub fn monitor(mut self, monitor: QemuOptSerial) -> QemuOpt {
        self.monitor = Some(monitor);
        self
    }

    #[must_use]
    pub fn no_graphic(mut self) -> QemuOpt {
        self.no_graphic = true;
        self
    }

    #[must_use]
    pub fn ram_size(mut self, ram_size: u32) -> QemuOpt {
        self.ram_size = Some(ram_size);
        self
    }

    #[must_use]
    pub fn serial(mut self, serial: QemuOptSerial) -> QemuOpt {
        self.serial = Some(serial);
        self
    }

    #[must_use]
    pub fn smp_cpus(mut self, smp_cpus: u32) -> QemuOpt {
        self.smp_cpus = Some(smp_cpus);
        self
    }

    #[must_use]
    pub fn snapshot(mut self) -> QemuOpt {
        self.snapshot = true;
        self
    }

    #[must_use]
    pub fn vga_pci(mut self) -> QemuOpt {
        self.vga_pci = true;
        self
    }

    #[must_use]
    pub fn do_not_start_cpu(mut self) -> QemuOpt {
        self.do_not_start_cpu = true;
        self
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn default_fmt_is_empty() {
        let opt = QemuOpt::default();
        assert_eq!(opt.to_string(), "");
    }

    #[test]
    fn drive_no_file_fmt() {
        let drive = QemuOptDrive {
            file: None,
            format: Some(QemuOptDiskImageFileFormat::raw),
            interface: Some(QemuOptDriveInterface::default()),
        };
        assert_eq!(drive.to_string(), " -drive format=raw,if=ide");
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

        let qemu_opt = QemuOpt::new()
            .machine("mps2-an385".to_string())
            .monitor(QemuOptSerial::null)
            .kernel(PathBuf::from("${TARGET_DIR}/example.elf"))
            .serial(QemuOptSerial::null)
            .no_graphic()
            .snapshot()
            .add_drive(
                QemuOptDrive::new()
                    .interface(QemuOptDriveInterface::none)
                    .format(QemuOptDiskImageFileFormat::qcow2)
                    .file(PathBuf::from("${TARGET_DIR}/dummy.qcow2")),
            )
            .do_not_start_cpu();
        let qemu_opt_str = qemu_opt.to_string();
        let qemu_opt_str_args = str_split_sort(&qemu_opt_str, " -");

        assert_eq!(qemu_opt_str_args, shell_config_args);
    }

    #[must_use]
    fn str_split_sort<'a>(s: &'a str, separator: &str) -> Vec<&'a str> {
        let mut v = s.split(separator).collect::<Vec<&str>>();
        v.sort_unstable();
        v
    }
}
