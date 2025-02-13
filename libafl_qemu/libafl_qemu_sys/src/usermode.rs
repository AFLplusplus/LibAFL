#[cfg(target_os = "linux")]
use core::{slice::from_raw_parts, str::from_utf8_unchecked};
#[cfg(feature = "python")]
use std::convert::Infallible;

#[cfg(target_os = "linux")]
use libc::{c_char, strlen};
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "python")]
use pyo3::{pyclass, pymethods, types::PyInt, Bound, IntoPyObject, Python};
use strum_macros::EnumIter;

use crate::MmapPerms;
#[cfg(target_os = "linux")]
use crate::{libafl_mapinfo, GuestAddr};

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter, PartialEq, Eq)]
#[repr(i32)]
pub enum VerifyAccess {
    Read = libc::PROT_READ,
    Write = libc::PROT_READ | libc::PROT_WRITE,
}

#[derive(Debug)]
#[repr(C)]
#[cfg(target_os = "linux")]
#[cfg_attr(feature = "python", pyclass(unsendable))]
pub struct MapInfo {
    start: GuestAddr,
    end: GuestAddr,
    offset: GuestAddr,
    path: Option<String>,
    flags: i32,
    is_priv: i32,
}

#[cfg(target_os = "linux")]
#[cfg_attr(feature = "python", pymethods)]
impl MapInfo {
    #[must_use]
    pub fn start(&self) -> GuestAddr {
        self.start
    }

    #[must_use]
    pub fn end(&self) -> GuestAddr {
        self.end
    }

    #[must_use]
    pub fn offset(&self) -> GuestAddr {
        self.offset
    }

    #[must_use]
    pub fn path(&self) -> Option<&String> {
        self.path.as_ref()
    }

    #[must_use]
    pub fn flags(&self) -> MmapPerms {
        MmapPerms::try_from(self.flags).unwrap()
    }

    #[must_use]
    pub fn is_priv(&self) -> bool {
        self.is_priv != 0
    }
}

impl MmapPerms {
    #[must_use]
    pub fn readable(&self) -> bool {
        matches!(
            self,
            MmapPerms::Read
                | MmapPerms::ReadWrite
                | MmapPerms::ReadExecute
                | MmapPerms::ReadWriteExecute
        )
    }

    #[must_use]
    pub fn writable(&self) -> bool {
        matches!(
            self,
            MmapPerms::Write
                | MmapPerms::ReadWrite
                | MmapPerms::WriteExecute
                | MmapPerms::ReadWriteExecute
        )
    }

    #[must_use]
    pub fn executable(&self) -> bool {
        matches!(
            self,
            MmapPerms::Execute
                | MmapPerms::ReadExecute
                | MmapPerms::WriteExecute
                | MmapPerms::ReadWriteExecute
        )
    }
}

#[cfg(feature = "python")]
impl<'py> IntoPyObject<'py> for MmapPerms {
    type Target = PyInt;
    type Output = Bound<'py, Self::Target>;
    type Error = Infallible;

    fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
        let n: i32 = self.into();
        n.into_pyobject(py)
    }
}

#[cfg(target_os = "linux")]
impl From<libafl_mapinfo> for MapInfo {
    fn from(map_info: libafl_mapinfo) -> Self {
        let path: Option<String> = if map_info.path.is_null() {
            None
        } else {
            unsafe {
                Some(
                    from_utf8_unchecked(from_raw_parts(
                        map_info.path as *const u8,
                        strlen(map_info.path as *const c_char),
                    ))
                    .to_string(),
                )
            }
        };

        MapInfo {
            start: map_info.start,
            end: map_info.end,
            offset: map_info.offset,
            path,
            flags: map_info.flags,
            is_priv: map_info.is_priv,
        }
    }
}
