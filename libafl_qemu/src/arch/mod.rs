#[cfg(cpu_target = "aarch64")]
pub mod aarch64;
#[cfg(all(cpu_target = "aarch64", not(feature = "clippy")))]
pub use aarch64::*;

#[cfg(cpu_target = "arm")]
pub mod arm;
#[cfg(all(cpu_target = "arm", not(feature = "clippy")))]
pub use arm::*;

#[cfg(cpu_target = "i386")]
pub mod i386;
#[cfg(all(cpu_target = "i386", not(feature = "clippy")))]
pub use i386::*;

#[cfg(cpu_target = "x86_64")]
pub mod x86_64;
#[cfg(cpu_target = "x86_64")]
pub use x86_64::*;

#[cfg(cpu_target = "mips")]
pub mod mips;
#[cfg(cpu_target = "mips")]
pub use mips::*;

#[cfg(cpu_target = "ppc")]
pub mod ppc;
#[cfg(cpu_target = "ppc")]
pub use ppc::*;

#[cfg(cpu_target = "hexagon")]
pub mod hexagon;
#[cfg(cpu_target = "hexagon")]
pub use hexagon::*;
