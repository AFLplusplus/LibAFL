#[cfg(feature = "injections")]
pub mod injections;
#[cfg(feature = "injections")]
pub use injections::InjectionModule;

#[cfg(not(cpu_target = "hexagon"))]
pub mod snapshot;
#[cfg(not(cpu_target = "hexagon"))]
pub use snapshot::{IntervalSnapshotFilter, SnapshotModule};

#[cfg(not(cpu_target = "hexagon"))]
pub mod asan_host;
#[cfg(not(cpu_target = "hexagon"))]
pub use asan_host::AsanHostModule;

#[cfg(not(cpu_target = "hexagon"))]
pub mod asan_guest;
#[cfg(not(cpu_target = "hexagon"))]
pub use asan_guest::AsanGuestModule;
pub mod redirect_stdin;
pub use redirect_stdin::*;

pub mod redirect_stdout;
pub use redirect_stdout::*;
