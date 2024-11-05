use core::{
    fmt,
    fmt::{Display, Formatter},
};
use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};

use getset::Getters;
use libafl_derive;
use strum_macros;
use typed_builder::TypedBuilder;

use crate::{Qemu, QemuInitError};

pub(super) static QEMU_CONFIG: OnceLock<QemuConfig> = OnceLock::new();

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

#[derive(Debug, Clone, Default, TypedBuilder)]
pub struct Drive {
    #[builder(default, setter(strip_option, into))]
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

#[derive(Debug, strum_macros::Display, Clone)]
#[strum(prefix = "-serial ", serialize_all = "lowercase")]
pub enum Serial {
    None,
    Null,
    Stdio,
}

#[derive(Debug, strum_macros::Display, Clone)]
#[strum(prefix = "-monitor ", serialize_all = "lowercase")]
pub enum Monitor {
    None,
    Null,
    Stdio,
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
#[builder(build_method(into = Result<Qemu, QemuInitError>), builder_method(vis = "pub(crate)",
    doc = "Since Qemu is a zero sized struct, this is not a completely standard builder pattern. \
    The Qemu configuration is not stored in the Qemu struct after build() but in QEMU_CONFIG \
    Therefore, to use the derived builder and avoid boilerplate a builder for QemuConfig is \
    derived. \
    The QemuConfig::builder is called in Qemu::builder() which is the only place where it should \
    be called, in this way the one to one matching of Qemu and QemuConfig is enforced. Therefore \
    its visibility is pub(crate)"))]
#[getset(get = "pub")]
pub struct QemuConfig {
    #[cfg(feature = "systemmode")]
    #[builder(default, setter(strip_option))]
    accelerator: Option<Accelerator>,
    #[cfg(feature = "systemmode")]
    #[builder(default, setter(strip_option, into))]
    bios: Option<Bios>,
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
    #[cfg(feature = "usermode")]
    #[builder(setter(into))]
    program: Program,
} // Adding something here? Please leave Program as the last field

impl From<QemuConfig> for Result<Qemu, QemuInitError> {
    /// This method is necessary to make the API resemble a typical builder pattern, i.e.
    /// `Qemu::builder().foo(bar).build()`, while still leveraging `TypedBuilder` for this
    /// non-standard use case where `Qemu` doesn't store the configuration.
    /// Internally, `TypedBuilder` is used to generate a builder for `QemuConfig`.
    /// This `QemuConfig.into()` method is used by the derived `QemuConfigBuilder.build()`
    /// to go from `QemuConfigBuilder` to `QemuConfig`, and finally to `Qemu` in one fn.
    ///
    /// # Errors
    /// returns `QemuInitError` if the Qemu initialization fails, including cases where Qemu has
    /// already been initialized.
    fn from(config: QemuConfig) -> Self {
        let args = config
            .to_string()
            .split(' ')
            .map(ToString::to_string)
            .collect::<Vec<String>>();
        let qemu = Qemu::init(&args)?;
        QEMU_CONFIG
            .set(config)
            .map_err(|_| unreachable!("BUG: QEMU_CONFIG was already set but Qemu was not init!"))?;
        Ok(qemu)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[cfg(feature = "usermode")]
    fn usermode() {
        let program = "/bin/pwd";
        let qemu = Qemu::builder().program("/bin/pwd").build().unwrap();
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
