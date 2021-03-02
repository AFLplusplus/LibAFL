//! A generic sharememory region to be used by any functions (queues or feedbacks
// too.)

#[cfg(feature = "std")]
#[cfg(unix)]
pub use unix_shmem::UnixShMem;

#[cfg(feature = "std")]
#[cfg(windows)]
pub use unix_shmem::Win32ShMem;

use alloc::string::{String, ToString};
use core::fmt::Debug;
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::env;

use crate::Error;

/// Description of a shared map.
/// May be used to restore the map by id.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct ShMemDescription {
    /// Size of this map
    size: usize,
    /// of name of this map, as fixed 20 bytes c-string
    str_bytes: [u8; 20],
}

/// A Shared map
pub trait ShMem: Sized + Debug {
    /// Creates a new map with the given size
    fn new_map(map_size: usize) -> Result<Self, Error>;

    /// Creates a new reference to the same map
    fn clone_ref(old_ref: &Self) -> Result<Self, Error> {
        Self::existing_from_shm_slice(old_ref.shm_slice(), old_ref.map().len())
    }

    /// Creates a nes variable with the given name, strigified to 20 bytes.
    fn existing_from_shm_slice(map_str_bytes: &[u8; 20], map_size: usize) -> Result<Self, Error>;

    /// Initialize from a shm_str with fixed len of 20
    fn existing_from_shm_str(shm_str: &str, map_size: usize) -> Result<Self, Error> {
        let mut slice: [u8; 20] = [0; 20];
        for (i, val) in shm_str.as_bytes().iter().enumerate() {
            slice[i] = *val;
        }
        Self::existing_from_shm_slice(&slice, map_size)
    }

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

    /// Describe this shared map in a recreatable fashion
    fn description(&self) -> ShMemDescription {
        ShMemDescription {
            size: self.map().len(),
            str_bytes: *self.shm_slice(),
        }
    }

    /// Create a map from a map description
    fn existing_from_description(description: &ShMemDescription) -> Result<Self, Error> {
        Self::existing_from_shm_slice(&description.str_bytes, description.size)
    }

    /// Write this map's config to env
    #[cfg(feature = "std")]
    fn write_to_env(&self, env_name: &str) -> Result<(), Error> {
        let map_size = self.map().len();
        let map_size_env = format!("{}_SIZE", env_name);
        env::set_var(env_name, self.shm_str());
        env::set_var(map_size_env, format!("{}", map_size));
        Ok(())
    }

    /// Reads an existing map config from env vars, then maps it
    #[cfg(feature = "std")]
    fn existing_from_env(env_name: &str) -> Result<Self, Error> {
        let map_shm_str = env::var(env_name)?;
        let map_size = str::parse::<usize>(&env::var(format!("{}_SIZE", env_name))?)?;
        Self::existing_from_shm_str(&map_shm_str, map_size)
    }
}

#[cfg(unix)]
#[cfg(feature = "std")]
pub mod unix_shmem {

    use core::{mem::size_of, ptr, slice};
    use libc::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_ushort, c_void};
    use std::ffi::CStr;

    use crate::Error;

    use super::ShMem;

    #[cfg(unix)]
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

    #[cfg(unix)]
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

    #[cfg(unix)]
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

    /// The default Sharedmap impl for unix using shmctl & shmget
    #[cfg(unix)]
    #[derive(Clone, Debug)]
    pub struct UnixShMem {
        pub shm_str: [u8; 20],
        pub shm_id: c_int,
        pub map: *mut u8,
        pub map_size: usize,
    }

    #[cfg(unix)]
    impl ShMem for UnixShMem {
        fn existing_from_shm_slice(
            map_str_bytes: &[u8; 20],
            map_size: usize,
        ) -> Result<Self, Error> {
            unsafe {
                let str_bytes = map_str_bytes as *const [u8; 20] as *const libc::c_char;
                Self::from_str(CStr::from_ptr(str_bytes), map_size)
            }
        }

        fn new_map(map_size: usize) -> Result<Self, Error> {
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

    /// Deinit sharedmaps on drop
    impl Drop for UnixShMem {
        fn drop(&mut self) {
            unsafe {
                afl_shmem_deinit(self);
            }
        }
    }

    /// Create an uninitialized shmap
    #[cfg(unix)]
    const fn afl_shmem_unitialized() -> UnixShMem {
        UnixShMem {
            shm_str: [0; 20],
            shm_id: -1,
            map: 0 as *mut c_uchar,
            map_size: 0,
        }
    }

    #[cfg(unix)]
    impl UnixShMem {
        pub fn from_str(shm_str: &CStr, map_size: usize) -> Result<Self, Error> {
            let mut ret = afl_shmem_unitialized();
            let map = unsafe { afl_shmem_by_str(&mut ret, shm_str, map_size) };
            if !map.is_null() {
                Ok(ret)
            } else {
                Err(Error::Unknown(format!(
                    "Could not allocate map with id {:?} and size {}",
                    shm_str, map_size
                )))
            }
        }

        pub fn new(map_size: usize) -> Result<Self, Error> {
            let mut ret = afl_shmem_unitialized();
            let map = unsafe { afl_shmem_init(&mut ret, map_size) };
            if !map.is_null() {
                Ok(ret)
            } else {
                Err(Error::Unknown(format!(
                    "Could not allocate map of size {}",
                    map_size
                )))
            }
        }
    }

    /// Deinitialize this shmem instance
    unsafe fn afl_shmem_deinit(shm: *mut UnixShMem) {
        if shm.is_null() || (*shm).map.is_null() {
            /* Serialized map id */
            // Not set or not initialized;
            return;
        }
        (*shm).shm_str[0 as usize] = 0u8;
        shmctl((*shm).shm_id, 0 as c_int, ptr::null_mut());
        (*shm).map = ptr::null_mut();
    }

    /// Functions to create Shared memory region, for observation channels and
    /// opening inputs and stuff.
    unsafe fn afl_shmem_init(shm: *mut UnixShMem, map_size: usize) -> *mut c_uchar {
        (*shm).map_size = map_size;
        (*shm).map = ptr::null_mut();
        (*shm).shm_id = shmget(
            0 as c_int,
            map_size as c_ulong,
            0o1000 as c_int | 0o2000 as c_int | 0o600 as c_int,
        );
        if (*shm).shm_id < 0 as c_int {
            (*shm).shm_str[0] = 0u8;
            return ptr::null_mut();
        }
        snprintf(
            (*shm).shm_str.as_mut_ptr() as *mut c_char,
            size_of::<[c_char; 20]>() as c_ulong,
            b"%d\x00" as *const u8 as *const c_char,
            (*shm).shm_id,
        );
        (*shm).shm_str
            [(size_of::<[c_char; 20]>() as c_ulong).wrapping_sub(1 as c_int as c_ulong) as usize] =
            0u8;
        (*shm).map = shmat((*shm).shm_id, ptr::null(), 0 as c_int) as *mut c_uchar;
        if (*shm).map == -(1 as c_int) as *mut c_void as *mut c_uchar || (*shm).map.is_null() {
            shmctl((*shm).shm_id, 0 as c_int, ptr::null_mut());
            (*shm).shm_id = -(1 as c_int);
            (*shm).shm_str[0 as c_int as usize] = 0u8;
            return ptr::null_mut();
        }
        (*shm).map
    }

    /// Uses a shmap id string to open a shared map
    unsafe fn afl_shmem_by_str(
        shm: *mut UnixShMem,
        shm_str: &CStr,
        map_size: usize,
    ) -> *mut c_uchar {
        if shm.is_null() || shm_str.to_bytes().is_empty() || map_size == 0 {
            return ptr::null_mut();
        }
        (*shm).map = ptr::null_mut();
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
        (*shm).map = shmat((*shm).shm_id, ptr::null(), 0 as c_int) as *mut c_uchar;
        if (*shm).map == -(1 as c_int) as *mut c_void as *mut c_uchar {
            (*shm).map = ptr::null_mut();
            (*shm).map_size = 0;
            (*shm).shm_str[0] = 0u8;
            return ptr::null_mut();
        }
        (*shm).map
    }
}

#[cfg(windows)]
#[cfg(feature = "std")]
pub mod shmem {

    use core::{mem::size_of, slice};
    use std::ffi::CStr;

    use super::ShMem;
    use crate::Error;

    /// The default Sharedmap impl for windows using shmctl & shmget
    #[derive(Clone, Debug)]
    pub struct Win32ShMem {
        pub filename: [u8; 64],
        pub handle: windows::win32::system_services::HANDLE,
        pub map: *mut u8,
        pub map_size: usize,
    }

    // TODO complete
}

#[cfg(test)]
mod tests {

    #[cfg(feature = "std")]
    use super::{ShMem, UnixShMem};

    #[cfg(feature = "std")]
    #[test]
    fn test_str_conversions() {
        let mut shm_str: [u8; 20] = [0; 20];
        shm_str[0] = 'A' as u8;
        shm_str[1] = 'B' as u8;
        shm_str[2] = 'C' as u8;
        let faux_shmem = UnixShMem {
            shm_id: 0,
            shm_str,
            map: 0 as *mut u8,
            map_size: 20,
        };
        let str = faux_shmem.shm_str();
        assert_eq!(str, "ABC");
    }
}
