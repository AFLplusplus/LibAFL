use libafl_qemu_sys::GuestPhysAddr;

use crate::modules::{
    HasInstrumentationFilter, IsFilter, QemuInstrumentationAddressRangeFilter,
    QemuInstrumentationPagingFilter,
};

pub trait StdInstrumentationFilter:
    HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter>
    + HasInstrumentationFilter<QemuInstrumentationPagingFilter>
{
}

impl<Head> crate::modules::StdInstrumentationFilter for (Head, ()) where
    Head: HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter>
        + HasInstrumentationFilter<QemuInstrumentationPagingFilter>
{
}

impl StdInstrumentationFilter for () {}

pub trait IsPagingFilter: IsFilter<FilterParameter = Option<GuestPhysAddr>> {}

impl IsPagingFilter for QemuInstrumentationPagingFilter {}
