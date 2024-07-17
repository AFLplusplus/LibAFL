#[cfg(not(cpu_target = "hexagon"))]
pub mod drcov;
#[cfg(not(cpu_target = "hexagon"))]
pub use drcov::DrCovModule;

#[cfg(feature = "injections")]
pub mod injections;
#[cfg(feature = "injections")]
pub use injections::InjectionModule;

#[cfg(not(cpu_target = "hexagon"))]
pub mod snapshot;
#[cfg(not(cpu_target = "hexagon"))]
pub use snapshot::IntervalSnapshotFilter;
#[cfg(not(cpu_target = "hexagon"))]
pub use snapshot::SnapshotModule;

#[cfg(not(cpu_target = "hexagon"))]
pub mod asan;
#[cfg(not(cpu_target = "hexagon"))]
pub use asan::{init_qemu_with_asan, AsanModule};

#[cfg(not(cpu_target = "hexagon"))]
pub mod asan_guest;
#[cfg(not(cpu_target = "hexagon"))]
pub use asan_guest::{init_qemu_with_asan_guest, AsanGuestModule};

use crate::modules::{HasInstrumentationFilter, QemuInstrumentationAddressRangeFilter};

pub trait StdInstrumentationFilter:
    HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter>
{
}

impl<Head> StdInstrumentationFilter for (Head, ()) where
    Head: HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter>
{
}

impl StdInstrumentationFilter for () {}
