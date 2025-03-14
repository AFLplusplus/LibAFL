#[cfg(feature = "injections")]
pub mod injections;
#[cfg(feature = "injections")]
pub use injections::InjectionModule;

#[cfg(not(cpu_target = "hexagon"))]
pub mod snapshot;
#[cfg(not(cpu_target = "hexagon"))]
pub use snapshot::{IntervalSnapshotFilter, SnapshotModule};

#[cfg(not(cpu_target = "hexagon"))]
pub mod asan;
#[cfg(not(cpu_target = "hexagon"))]
pub use asan::AsanModule;

#[cfg(not(cpu_target = "hexagon"))]
pub mod asan_guest;
#[cfg(not(cpu_target = "hexagon"))]
pub use asan_guest::AsanGuestModule;
#[cfg(not(cpu_target = "hexagon"))]
pub mod redirect_stdin;
#[cfg(not(cpu_target = "hexagon"))]
pub use redirect_stdin::*;
