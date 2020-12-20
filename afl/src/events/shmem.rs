//! A generic sharememory region to be used by any functions (queues or feedbacks
// too.)

use alloc::string::String;
#[cfg(feature = "std")]
use core::{mem::size_of, slice};
#[cfg(feature = "std")]
use libc::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_ushort, c_void};
#[cfg(feature = "std")]
use std::{env, ffi::CStr};

use crate::AflError;

extern "C" {
    #[cfg(feature = "std")]
    fn snprintf(_: *mut c_char, _: c_ulong, _: *const c_char, _: ...) -> c_int;
    #[cfg(feature = "std")]
    fn strncpy(_: *mut c_char, _: *const c_char, _: c_ulong) -> *mut c_char;
    #[cfg(feature = "std")]
    fn shmctl(__shmid: c_int, __cmd: c_int, __buf: *mut shmid_ds) -> c_int;
    #[cfg(feature = "std")]
    fn shmget(__key: c_int, __size: c_ulong, __shmflg: c_int) -> c_int;
    #[cfg(feature = "std")]
    fn shmat(__shmid: c_int, __shmaddr: *const c_void, __shmflg: c_int) -> *mut c_void;
}

#[cfg(feature = "std")]
#[derive(Copy, Clone)]
#[repr(C)]
struct ipc_perm {
    pub __key: c_int,
    pub uid: c_uint,
    pub gid: c_uint,
    pub cuid: c_uint,
    pub cgid: c_uint,
    pub mode: c_ushort,
    pub __pad1: c_ushort,
    pub __seq: c_ushort,
    pub __pad2: c_ushort,
    pub __glibc_reserved1: c_ulong,
    pub __glibc_reserved2: c_ulong,
}

#[cfg(feature = "std")]
#[derive(Copy, Clone)]
#[repr(C)]
struct shmid_ds {
    pub shm_perm: ipc_perm,
    pub shm_segsz: c_ulong,
    pub shm_atime: c_long,
    pub shm_dtime: c_long,
    pub shm_ctime: c_long,
    pub shm_cpid: c_int,
    pub shm_lpid: c_int,
    pub shm_nattch: c_ulong,
    pub __glibc_reserved4: c_ulong,
    pub __glibc_reserved5: c_ulong,
}

/// A Shared map
pub trait ShMem: Sized {
    /// Creates a nes variable with the given name, strigified to 20 bytes.
    fn existing_from_shm_slice(map_str_bytes: &[u8; 20], map_size: usize)
        -> Result<Self, AflError>;

    /// Initialize from a shm_str with fixed len of 20
    fn existing_from_shm_str(shm_str: &str, map_size: usize) -> Result<Self, AflError> {
        let mut slice: [u8; 20] = [0; 20];
        for (i, val) in shm_str.as_bytes().iter().enumerate() {
            slice[i] = *val;
        }
        Self::existing_from_shm_slice(&slice, map_size)
    }

    /// Creates a new map with the given size
    fn new_map(map_size: usize) -> Result<Self, AflError>;

    /// The string to identify this shm
    fn shm_str(&self) -> String {
        let bytes = self.shm_slice();
        let eof_pos = bytes.iter().position(|&c| c == 0).unwrap();
        alloc::str::from_utf8(&bytes[..eof_pos])
            .unwrap()
            .to_string()
    }

    /// Let's just fix this to a large enough buf
    fn shm_slice(&self) -> &[u8; 20];

    /// The actual shared map, in memory
    fn map(&self) -> &[u8];

    /// The actual shared map, mutable
    fn map_mut(&mut self) -> &mut [u8];

    /// Write this map's config to env
    #[cfg(feature = "std")]
    fn write_to_env(&self, env_name: &str) -> Result<(), AflError> {
        let map_size = self.map().len();
        let map_size_env = format!("{}_SIZE", env_name);
        env::set_var(env_name, self.shm_str());
        env::set_var(map_size_env, format!("{}", map_size));
        Ok(())
    }

    /// Reads an existing map config from env vars, then maps it
    #[cfg(feature = "std")]
    fn existing_from_env(env_name: &str) -> Result<Self, AflError> {
        let map_shm_str = env::var(env_name)?;
        let map_size = str::parse::<usize>(&env::var(format!("{}_SIZE", env_name))?)?;
        Self::existing_from_shm_str(&map_shm_str, map_size)
    }
}

#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct AflShmem {
    pub shm_str: [u8; 20],
    pub shm_id: c_int,
    pub map: *mut u8,
    pub map_size: usize,
}

#[cfg(feature = "std")]
impl ShMem for AflShmem {
    fn existing_from_shm_slice(
        map_str_bytes: &[u8; 20],
        map_size: usize,
    ) -> Result<Self, AflError> {
        unsafe {
            let str_bytes = map_str_bytes as *const [u8; 20] as *const libc::c_char;
            Self::from_str(CStr::from_ptr(str_bytes), map_size)
        }
    }

    fn new_map(map_size: usize) -> Result<Self, AflError> {
        Self::new(map_size)
    }

    fn shm_slice(&self) -> &[u8; 20] {
        &self.shm_str
    }

    fn map(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.map, self.map_size) }
    }

    fn map_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.map, self.map_size) }
    }
}

#[cfg(feature = "std")]
/// Deinit sharedmaps on drop
impl Drop for AflShmem {
    fn drop(&mut self) {
        unsafe {
            afl_shmem_deinit(self);
        }
    }
}

#[cfg(feature = "std")]
/// Create an uninitialized shmap
const fn afl_shmem_unitialized() -> AflShmem {
    AflShmem {
        shm_str: [0; 20],
        shm_id: -1,
        map: 0 as *mut c_uchar,
        map_size: 0,
    }
}

#[cfg(feature = "std")]
impl AflShmem {
    pub fn from_str(shm_str: &CStr, map_size: usize) -> Result<Self, AflError> {
        let mut ret = afl_shmem_unitialized();
        let map = unsafe { afl_shmem_by_str(&mut ret, shm_str, map_size) };
        if map != 0 as *mut u8 {
            Ok(ret)
        } else {
            Err(AflError::Unknown(format!(
                "Could not allocate map with id {:?} and size {}",
                shm_str, map_size
            )))
        }
    }

    pub fn new(map_size: usize) -> Result<Self, AflError> {
        let mut ret = afl_shmem_unitialized();
        let map = unsafe { afl_shmem_init(&mut ret, map_size) };
        if map != 0 as *mut u8 {
            Ok(ret)
        } else {
            Err(AflError::Unknown(format!(
                "Could not allocate map of size {}",
                map_size
            )))
        }
    }
}

#[cfg(feature = "std")]
/// Deinitialize this shmem instance
unsafe fn afl_shmem_deinit(shm: *mut AflShmem) {
    if shm.is_null() || (*shm).map.is_null() {
        /* Serialized map id */
        // Not set or not initialized;
        return;
    }
    (*shm).shm_str[0 as usize] = '\u{0}' as u8;
    shmctl((*shm).shm_id, 0 as c_int, 0 as *mut shmid_ds);
    (*shm).map = 0 as *mut c_uchar;
}

#[cfg(feature = "std")]
/// Functions to create Shared memory region, for observation channels and
/// opening inputs and stuff.
unsafe fn afl_shmem_init(shm: *mut AflShmem, map_size: usize) -> *mut c_uchar {
    (*shm).map_size = map_size;
    (*shm).map = 0 as *mut c_uchar;
    (*shm).shm_id = shmget(
        0 as c_int,
        map_size as c_ulong,
        0o1000 as c_int | 0o2000 as c_int | 0o600 as c_int,
    );
    if (*shm).shm_id < 0 as c_int {
        (*shm).shm_str[0] = '\u{0}' as u8;
        return 0 as *mut c_uchar;
    }
    snprintf(
        (*shm).shm_str.as_mut_ptr() as *mut i8,
        size_of::<[c_char; 20]>() as c_ulong,
        b"%d\x00" as *const u8 as *const c_char,
        (*shm).shm_id,
    );
    (*shm).shm_str
        [(size_of::<[c_char; 20]>() as c_ulong).wrapping_sub(1 as c_int as c_ulong) as usize] =
        '\u{0}' as u8;
    (*shm).map = shmat((*shm).shm_id, 0 as *const c_void, 0 as c_int) as *mut c_uchar;
    if (*shm).map == -(1 as c_int) as *mut c_void as *mut c_uchar || (*shm).map.is_null() {
        shmctl((*shm).shm_id, 0 as c_int, 0 as *mut shmid_ds);
        (*shm).shm_id = -(1 as c_int);
        (*shm).shm_str[0 as c_int as usize] = '\u{0}' as u8;
        return 0 as *mut c_uchar;
    }
    return (*shm).map;
}

#[cfg(feature = "std")]
/// Uses a shmap id string to open a shared map
unsafe fn afl_shmem_by_str(shm: *mut AflShmem, shm_str: &CStr, map_size: usize) -> *mut c_uchar {
    if shm.is_null() || shm_str.to_bytes().len() == 0 || map_size == 0 {
        return 0 as *mut c_uchar;
    }
    (*shm).map = 0 as *mut c_uchar;
    (*shm).map_size = map_size;
    strncpy(
        (*shm).shm_str.as_mut_ptr() as *mut c_char,
        shm_str.as_ptr() as *const c_char,
        (size_of::<[c_char; 20]>() as c_ulong).wrapping_sub(1 as c_int as c_ulong),
    );
    (*shm).shm_id = shm_str
        .to_str()
        .expect(&format!("illegal shm_str {:?}", shm_str))
        .parse::<i32>()
        .unwrap();
    (*shm).map = shmat((*shm).shm_id, 0 as *const c_void, 0 as c_int) as *mut c_uchar;
    if (*shm).map == -(1 as c_int) as *mut c_void as *mut c_uchar {
        (*shm).map = 0 as *mut c_uchar;
        (*shm).map_size = 0;
        (*shm).shm_str[0] = '\u{0}' as u8;
        return 0 as *mut c_uchar;
    }
    return (*shm).map;
}

#[cfg(test)]
mod tests {
    use super::{AflShmem, ShMem};

    #[cfg(feature = "std")]
    #[test]
    fn test_str_conversions() {
        let mut shm_str: [u8; 20] = [0; 20];
        shm_str[0] = 'A' as u8;
        shm_str[1] = 'B' as u8;
        shm_str[2] = 'C' as u8;
        let faux_shmem = AflShmem {
            shm_id: 0,
            shm_str,
            map: 0 as *mut u8,
            map_size: 20,
        };
        let str = faux_shmem.shm_str();
        assert_eq!(str, "ABC");
    }
}
