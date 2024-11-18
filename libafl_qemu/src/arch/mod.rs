#[cfg(feature = "aarch64")]
pub mod aarch64;
#[cfg(all(feature = "aarch64", not(feature = "clippy")))]
pub use aarch64::*;

#[cfg(feature = "arm")]
pub mod arm;
#[cfg(all(feature = "arm", not(feature = "clippy")))]
pub use arm::*;

#[cfg(feature = "i386")]
pub mod i386;
#[cfg(all(feature = "i386", not(feature = "clippy")))]
pub use i386::*;

#[cfg(feature = "x86_64")]
pub mod x86_64;
#[cfg(feature = "x86_64")]
pub use x86_64::*;

#[cfg(feature = "mips")]
pub mod mips;
#[cfg(feature = "mips")]
pub use mips::*;

#[cfg(feature = "ppc")]
pub mod ppc;
#[cfg(feature = "ppc")]
pub use ppc::*;

#[cfg(feature = "hexagon")]
pub mod hexagon;
#[cfg(feature = "hexagon")]
pub use hexagon::*;

#[cfg(any(feature = "riscv32", feature = "riscv64"))]
pub mod riscv;
#[cfg(any(feature = "riscv32", feature = "riscv64"))]
pub use riscv::*;
