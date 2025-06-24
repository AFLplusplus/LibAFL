use core::{
    fmt,
    fmt::{Display, Formatter},
};
use std::path::{Path, PathBuf};

use getset::Getters;
use libafl_derive;
use strum_macros;
use typed_builder::TypedBuilder;

#[cfg(feature = "systemmode")]
#[derive(Debug, strum_macros::Display, Clone)]
#[strum(prefix = "-accel ", serialize_all = "lowercase")]
pub enum Accelerator {
    Kvm,
    Tcg,
}

#[derive(Debug, strum_macros::Display, Clone)]
#[strum(prefix = "if=", serialize_all = "lowercase")]
pub enum DriveInterface {
    Floppy,
    Ide,
    Mtd,
    None,
    Pflash,
    Scsi,
    Sd,
    Virtio,
}

#[derive(Debug, strum_macros::Display, Clone)]
#[strum(prefix = "format=", serialize_all = "lowercase")]
pub enum DiskImageFileFormat {
    Qcow2,
    Raw,
}

#[derive(Debug, strum_macros::Display, Clone)]
#[strum(prefix = "cache=", serialize_all = "lowercase")]
pub enum DriveCache {
    WriteBack,
    None,
    WriteThrough,
    DirectSync,
    Unsafe,
}

#[derive(Debug, Clone, Default, TypedBuilder)]
pub struct Drive {
    #[builder(default, setter(strip_option, into))]
    file: Option<PathBuf>,
    #[builder(default, setter(strip_option))]
    format: Option<DiskImageFileFormat>,
    #[builder(default, setter(strip_option))]
    interface: Option<DriveInterface>,
    #[builder(default, setter(strip_option))]
    cache: Option<DriveCache>,
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
        if let Some(cache) = &self.cache {
            write!(f, "{}{cache}", separator())?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, TypedBuilder)]
pub struct Tcp {
    #[builder(default, setter(strip_option))]
    host: Option<String>,
    port: u16,
    #[builder(default, setter(strip_option))]
    server: Option<bool>,
    #[builder(default, setter(strip_option))]
    wait: Option<bool>,
    #[builder(default, setter(strip_option))]
    nodelay: Option<bool>,
    #[builder(default, setter(strip_option))]
    reconnect_ms: Option<usize>,
}

impl Display for Tcp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "tcp:{}", self.host.as_deref().unwrap_or(""))?;
        write!(f, ":{}", self.port)?;
        let server = match self.server {
            Some(true) => ",server=on",
            Some(false) => ",server=off",
            None => "",
        };
        write!(f, "{server}")?;
        let wait = match self.wait {
            Some(true) => ",wait=on",
            Some(false) => ",wait=off",
            None => "",
        };
        write!(f, "{wait}")?;
        let nodelay = match self.nodelay {
            Some(true) => ",nodelay=on",
            Some(false) => ",nodelay=off",
            None => "",
        };
        write!(f, "{nodelay}")?;
        if let Some(ms) = self.reconnect_ms {
            write!(f, "{ms}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum Serial {
    None,
    Null,
    Stdio,
    Tcp(Tcp),
}

impl Display for Serial {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "-serial ")?;
        match self {
            Serial::None => write!(f, "none"),
            Serial::Null => write!(f, "null"),
            Serial::Stdio => write!(f, "stdio"),
            Serial::Tcp(tcp) => write!(f, "{tcp}"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Monitor {
    None,
    Null,
    Stdio,
    Tcp(Tcp),
}

impl Display for Monitor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "-monitor ")?;
        match self {
            Monitor::None => write!(f, "none"),
            Monitor::Null => write!(f, "null"),
            Monitor::Stdio => write!(f, "stdio"),
            Monitor::Tcp(tcp) => write!(f, "{tcp}"),
        }
    }
}

/// Set the directory for the BIOS, VGA BIOS and keymaps.
/// Corresponds to the `-L` option of QEMU.
#[cfg(feature = "systemmode")]
#[derive(Debug, Clone)]
pub struct Bios {
    path: PathBuf,
}

#[cfg(feature = "systemmode")]
impl Display for Bios {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "-L {}", self.path.to_str().unwrap())
    }
}

#[cfg(feature = "systemmode")]
impl<R: AsRef<Path>> From<R> for Bios {
    fn from(path: R) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

#[cfg(feature = "systemmode")]
#[derive(Debug, Clone)]
pub struct Kernel {
    path: PathBuf,
}

#[cfg(feature = "systemmode")]
impl Display for Kernel {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "-kernel {}", self.path.to_str().unwrap())
    }
}

#[cfg(feature = "systemmode")]
impl<R: AsRef<Path>> From<R> for Kernel {
    fn from(path: R) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

#[cfg(feature = "systemmode")]
#[derive(Debug, Clone)]
pub struct AppendKernelCmd {
    cmdline: String,
}

#[cfg(feature = "systemmode")]
impl Display for AppendKernelCmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "-append {}", self.cmdline)
    }
}

#[cfg(feature = "systemmode")]
impl<R: AsRef<str>> From<R> for AppendKernelCmd {
    fn from(cmdline: R) -> Self {
        Self {
            cmdline: cmdline.as_ref().to_string(),
        }
    }
}

#[cfg(feature = "systemmode")]
#[derive(Debug, Clone)]
pub struct InitRD {
    path: PathBuf,
}

#[cfg(feature = "systemmode")]
impl Display for InitRD {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "-initrd {}", self.path.to_str().unwrap())
    }
}

#[cfg(feature = "systemmode")]
impl<R: AsRef<Path>> From<R> for InitRD {
    fn from(path: R) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoadVM {
    path: PathBuf,
}

impl Display for LoadVM {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "-loadvm {}", self.path.to_str().unwrap())
    }
}

impl<R: AsRef<Path>> From<R> for LoadVM {
    fn from(path: R) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Machine {
    name: String,
}

impl Display for Machine {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "-machine {}", self.name)
    }
}

impl<R: AsRef<str>> From<R> for Machine {
    fn from(name: R) -> Self {
        Self {
            name: name.as_ref().to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Cpu {
    model: String,
}

impl Display for Cpu {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "-cpu {}", self.model)
    }
}

impl<R: AsRef<str>> From<R> for Cpu {
    fn from(model: R) -> Self {
        Self {
            model: model.as_ref().to_string(),
        }
    }
}

#[derive(Debug, Clone, strum_macros::Display)]
pub enum Snapshot {
    #[strum(serialize = "-snapshot")]
    ENABLE,
    #[strum(serialize = "")]
    DISABLE,
}

impl From<bool> for Snapshot {
    fn from(snapshot: bool) -> Self {
        if snapshot {
            Snapshot::ENABLE
        } else {
            Snapshot::DISABLE
        }
    }
}

/// When set to DISABLE, corresponds to the `-S` option of QEMU.
#[derive(Debug, Clone, strum_macros::Display)]
pub enum StartCPU {
    #[strum(serialize = "")]
    ENABLE,
    #[strum(serialize = "-S")]
    DISABLE,
}

impl From<bool> for StartCPU {
    fn from(start_cpu: bool) -> Self {
        if start_cpu {
            StartCPU::ENABLE
        } else {
            StartCPU::DISABLE
        }
    }
}

#[derive(Debug, Clone, strum_macros::Display)]
pub enum NoGraphic {
    #[strum(serialize = "-nographic")]
    ENABLE,
    #[strum(serialize = "")]
    DISABLE,
}

impl From<bool> for NoGraphic {
    fn from(no_graphic: bool) -> Self {
        if no_graphic {
            NoGraphic::ENABLE
        } else {
            NoGraphic::DISABLE
        }
    }
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

impl From<bool> for VgaPci {
    fn from(vga_pci: bool) -> Self {
        if vga_pci {
            VgaPci::ENABLE
        } else {
            VgaPci::DISABLE
        }
    }
}

#[cfg(feature = "systemmode")]
#[derive(Debug, Clone, strum_macros::Display)]
pub enum DefaultDevices {
    #[strum(serialize = "")]
    ENABLE,
    #[strum(serialize = "-nodefaults")]
    DISABLE,
}

#[cfg(feature = "systemmode")]
impl From<bool> for DefaultDevices {
    fn from(default_devices: bool) -> Self {
        if default_devices {
            DefaultDevices::ENABLE
        } else {
            DefaultDevices::DISABLE
        }
    }
}

#[cfg(feature = "usermode")]
#[derive(Debug, Clone)]
pub struct Program {
    path: PathBuf,
}

#[cfg(feature = "usermode")]
impl Display for Program {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path.to_str().unwrap())
    }
}

#[cfg(feature = "usermode")]
impl<R: AsRef<Path>> From<R> for Program {
    fn from(path: R) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

#[derive(Debug, Clone, libafl_derive::Display, TypedBuilder, Getters)]
pub struct QemuConfig {
    #[cfg(feature = "systemmode")]
    #[builder(default, setter(strip_option))]
    accelerator: Option<Accelerator>,
    #[cfg(feature = "systemmode")]
    #[builder(default, setter(strip_option, into))]
    bios: Option<Bios>,
    #[builder(default, setter(strip_option, into))]
    cpu: Option<Cpu>,
    #[builder(default, setter(into))]
    drives: Vec<Drive>,
    #[cfg(feature = "systemmode")]
    #[builder(default, setter(strip_option, into))]
    kernel: Option<Kernel>,
    #[builder(default, setter(strip_option, into))]
    load_vm: Option<LoadVM>,
    #[builder(default, setter(strip_option, into))]
    machine: Option<Machine>,
    #[builder(default, setter(strip_option))]
    monitor: Option<Monitor>,
    #[builder(default, setter(strip_option, into))]
    no_graphic: Option<NoGraphic>,
    #[builder(default, setter(strip_option))]
    ram_size: Option<RamSize>,
    #[builder(default, setter(strip_option))]
    serial: Option<Serial>,
    #[builder(default, setter(strip_option))]
    smp_cpus: Option<SmpCpus>,
    #[builder(default, setter(strip_option, into))]
    snapshot: Option<Snapshot>,
    #[builder(default, setter(strip_option, into))]
    vga_pci: Option<VgaPci>,
    #[builder(default, setter(strip_option, into))]
    start_cpu: Option<StartCPU>,
    #[cfg(feature = "systemmode")]
    #[builder(default, setter(strip_option, into))]
    default_devices: Option<DefaultDevices>,
    #[cfg(feature = "systemmode")]
    #[builder(default, setter(strip_option, into))]
    append_kernel_cmd: Option<AppendKernelCmd>,
    #[cfg(feature = "systemmode")]
    #[builder(default, setter(strip_option, into))]
    initrd: Option<InitRD>,
    #[cfg(feature = "usermode")]
    #[builder(setter(into))]
    program: Program,
} // Adding something here? Please leave Program as the last field

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "usermode")]
    use crate::Qemu;

    #[test]
    #[cfg(feature = "usermode")]
    fn usermode() {
        let program = "/bin/pwd";
        let qemu_config = QemuConfig::builder().program("/bin/pwd").build();
        let qemu = Qemu::init(qemu_config).unwrap();
        let config = qemu.get_config().unwrap();
        assert_eq!(config.to_string().trim(), program.trim());
    }

    #[test]
    fn drive_no_file_fmt() {
        let drive = Drive::builder()
            .format(DiskImageFileFormat::Raw)
            .interface(DriveInterface::Ide)
            .build();
        assert_eq!(drive.to_string(), "-drive format=raw,if=ide");
    }

    #[test]
    #[cfg(feature = "systemmode")]
    fn accelerator_kvm_to_string() {
        let accel = Accelerator::Kvm;
        assert_eq!(accel.to_string(), "-accel kvm");
    }
}
