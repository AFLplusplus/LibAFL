use std::fmt::Debug;

#[cfg(all(cpu_target = "x86_64", target_os = "linux"))]
pub mod intel_pt;
#[cfg(all(cpu_target = "x86_64", target_os = "linux"))]
pub use intel_pt::*;
use libafl_qemu_sys::GuestPhysAddr;

use crate::modules::{
    HasInstrumentationFilter, IsFilter, QemuInstrumentationAddressRangeFilter,
    QemuInstrumentationPagingFilter,
};

pub trait StdInstrumentationFilter:
    Debug
    + HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter>
    + HasInstrumentationFilter<QemuInstrumentationPagingFilter>
{
}

impl<Head> crate::modules::StdInstrumentationFilter for (Head, ()) where
    Head: HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter>
        + HasInstrumentationFilter<QemuInstrumentationPagingFilter>
        + Debug
{
}

impl StdInstrumentationFilter for () {}

pub trait IsPagingFilter: IsFilter<FilterParameter = Option<GuestPhysAddr>> {}

impl IsPagingFilter for QemuInstrumentationPagingFilter {}
