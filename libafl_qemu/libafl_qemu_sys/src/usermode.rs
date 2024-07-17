use core::{slice::from_raw_parts, str::from_utf8_unchecked};

use num_enum::{IntoPrimitive, TryFromPrimitive};
use paste::paste;
#[cfg(feature = "python")]
use pyo3::{pyclass, pymethods, IntoPy, PyObject, Python};
use strum_macros::EnumIter;

use crate::{extern_c_checked, libafl_mapinfo, strlen, GuestAddr, MmapPerms};

extern_c_checked! {
    pub fn qemu_user_init(argc: i32, argv: *const *const u8, envp: *const *const u8) -> i32;

    pub fn libafl_qemu_run() -> i32;

    pub fn libafl_load_addr() -> u64;
    pub fn libafl_get_brk() -> u64;
    pub fn libafl_set_brk(brk: u64) -> u64;

    pub static exec_path: *const u8;
    pub static guest_base: usize;
    pub static mut mmap_next_start: GuestAddr;

    pub static mut libafl_dump_core_hook: unsafe extern "C" fn(i32);
    pub static mut libafl_force_dfl: i32;
}

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
impl IntoPy<PyObject> for MmapPerms {
    fn into_py(self, py: Python) -> PyObject {
        let n: i32 = self.into();
        n.into_py(py)
    }
}
impl From<libafl_mapinfo> for MapInfo {
    fn from(map_info: libafl_mapinfo) -> Self {
        let path: Option<String> = if map_info.path.is_null() {
            None
        } else {
            unsafe {
                Some(
                    from_utf8_unchecked(from_raw_parts(
                        map_info.path as *const u8,
                        strlen(map_info.path as *const u8),
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
