//! A generic sharememory region to be used by any functions (queues or feedbacks
// too.)

#[cfg(all(feature = "std", unix))]
pub use unix_shmem::UnixShMem;

#[cfg(all(windows, feature = "std"))]
pub use shmem::Win32ShMem;

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
    pub size: usize,
    /// of name of this map, as fixed 20 bytes c-string
    pub str_bytes: [u8; 20],
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

/// shared maps that have an id can use this trait
pub trait HasFd {
    /// Retrieve the id of this shared map
    fn shm_id(&self) -> i32;
}

#[cfg(all(unix, feature = "std"))]
pub mod unix_shmem {

    use core::{mem::size_of, ptr, slice};
    use libc::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_ushort, c_void};
    #[cfg(target_os = "android")]
    use libc::{off_t, size_t, MAP_SHARED, O_RDWR, PROT_READ, PROT_WRITE};
    use std::ffi::CStr;
    #[cfg(target_os = "android")]
    use std::ffi::CString;

    use crate::Error;

    use super::{HasFd, ShMem};

    #[cfg(unix)]
    extern "C" {
        #[cfg(feature = "std")]
        fn snprintf(_: *mut c_char, _: c_ulong, _: *const c_char, _: ...) -> c_int;
        #[cfg(feature = "std")]
        fn strncpy(_: *mut c_char, _: *const c_char, _: c_ulong) -> *mut c_char;
        #[cfg(all(feature = "std", not(target_os = "android")))]
        fn shmctl(__shmid: c_int, __cmd: c_int, __buf: *mut shmid_ds) -> c_int;
        #[cfg(all(feature = "std", not(target_os = "android")))]
        fn shmget(__key: c_int, __size: c_ulong, __shmflg: c_int) -> c_int;
        #[cfg(all(feature = "std", not(target_os = "android")))]
        fn shmat(__shmid: c_int, __shmaddr: *const c_void, __shmflg: c_int) -> *mut c_void;
        #[cfg(all(feature = "std", target_os = "android"))]
        fn ioctl(fd: c_int, request: c_long, ...) -> c_int;
        #[cfg(all(feature = "std", target_os = "android"))]
        fn open(path: *const c_char, oflag: c_int, ...) -> c_int;
        #[cfg(all(feature = "std", target_os = "android"))]
        fn close(fd: c_int) -> c_int;
        #[cfg(all(feature = "std", target_os = "android"))]
        fn mmap(
            addr: *mut c_void,
            len: size_t,
            prot: c_int,
            flags: c_int,
            fd: c_int,
            offset: off_t,
        ) -> *mut c_void;

    }

    #[cfg(target_os = "android")]
    #[derive(Copy, Clone)]
    #[repr(C)]
    struct ashmem_pin {
        pub offset: c_uint,
        pub len: c_uint,
    }

    #[cfg(target_os = "android")]
    const ASHMEM_GET_SIZE: c_long = 0x00007704;
    #[cfg(target_os = "android")]
    const ASHMEM_UNPIN: c_long = 0x40087708;
    #[cfg(target_os = "android")]
    const ASHMEM_SET_NAME: c_long = 0x41007701;
    #[cfg(target_os = "android")]
    const ASHMEM_SET_SIZE: c_long = 0x40087703;
    #[cfg(target_os = "android")]
    const ASHMEM_DEVICE: &str = "/dev/ashmem";

    #[cfg(target_os = "android")]
    unsafe fn shmctl(__shmid: c_int, __cmd: c_int, _buf: *mut shmid_ds) -> c_int {
        if __cmd == 0 {
            let length = ioctl(__shmid, ASHMEM_GET_SIZE);

            let ap = ashmem_pin {
                offset: 0,
                len: length as u32,
            };

            let ret = ioctl(__shmid, ASHMEM_UNPIN, &ap);
            close(__shmid);
            ret
        } else {
            0
        }
    }

    #[cfg(target_os = "android")]
    unsafe fn shmget(__key: c_int, __size: c_ulong, __shmflg: c_int) -> c_int {
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();

        let path = CString::new(format!("{}{}", ASHMEM_DEVICE, boot_id).trim())
            .expect("CString::new failed!");
        let fd = open(path.as_ptr(), O_RDWR);

        let mut ourkey: [c_char; 20] = [0; 20];
        snprintf(
            ourkey.as_mut_ptr() as *mut c_char,
            size_of::<[c_char; 20]>() as c_ulong,
            b"%d\x00" as *const u8 as *const c_char,
            if __key == 0 { fd } else { __key },
        );

        if ioctl(fd, ASHMEM_SET_NAME, &ourkey) != 0 {
            close(fd);
            return 0;
        };

        if ioctl(fd, ASHMEM_SET_SIZE, __size) != 0 {
            close(fd);
            return 0;
        };

        fd
    }

    #[cfg(target_os = "android")]
    unsafe fn shmat(__shmid: c_int, __shmaddr: *const c_void, __shmflg: c_int) -> *mut c_void {
        let size = ioctl(__shmid, ASHMEM_GET_SIZE);
        if size < 0 {
            return 0 as *mut c_void;
        }

        let ptr = mmap(
            0 as *mut c_void,
            size as usize,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            __shmid,
            0,
        );
        if ptr == usize::MAX as *mut c_void {
            return 0 as *mut c_void;
        }

        ptr
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

    impl HasFd for UnixShMem {
        fn shm_id(&self) -> i32 {
            self.shm_id
        }
    }

    /// Deinit sharedmaps on drop
    impl Drop for UnixShMem {
        fn drop(&mut self) {
            unsafe {
                unix_shmem_deinit(self);
            }
        }
    }

    /// Create an uninitialized shmap
    #[cfg(unix)]
    const fn unix_shmem_unitialized() -> UnixShMem {
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
            let mut ret = unix_shmem_unitialized();
            let map = unsafe { unix_shmem_by_str(&mut ret, shm_str, map_size) };
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
            let mut ret = unix_shmem_unitialized();
            let map = unsafe { unix_shmem_init(&mut ret, map_size) };
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
    unsafe fn unix_shmem_deinit(shm: *mut UnixShMem) {
        if shm.is_null() || (*shm).map.is_null() {
            /* Serialized map id */
            // Not set or not initialized;
            return;
        }
        (*shm).shm_str[0_usize] = 0u8;
        shmctl((*shm).shm_id, 0 as c_int, ptr::null_mut());
        (*shm).map = ptr::null_mut();
    }

    /// Functions to create Shared memory region, for observation channels and
    /// opening inputs and stuff.
    unsafe fn unix_shmem_init(shm: *mut UnixShMem, map_size: usize) -> *mut c_uchar {
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
    unsafe fn unix_shmem_by_str(
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
            .unwrap_or_else(|_| panic!("illegal shm_str {:?}", shm_str))
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

#[cfg(all(feature = "std", windows))]
pub mod shmem {

    use super::ShMem;
    use crate::{
        bolts::bindings::{
            windows::win32::system_services::{
                CreateFileMappingA, MapViewOfFile, OpenFileMappingA, UnmapViewOfFile,
            },
            windows::win32::system_services::{BOOL, HANDLE, PAGE_TYPE, PSTR},
            windows::win32::windows_programming::CloseHandle,
        },
        Error,
    };

    use core::{ffi::c_void, ptr, slice};
    use uuid::Uuid;

    const INVALID_HANDLE_VALUE: isize = -1;
    const FILE_MAP_ALL_ACCESS: u32 = 0xf001f;

    /// The default Sharedmap impl for windows using shmctl & shmget
    #[derive(Clone, Debug)]
    pub struct Win32ShMem {
        pub shm_str: [u8; 20],
        pub handle: HANDLE,
        pub map: *mut u8,
        pub map_size: usize,
    }

    impl ShMem for Win32ShMem {
        fn existing_from_shm_slice(
            map_str_bytes: &[u8; 20],
            map_size: usize,
        ) -> Result<Self, Error> {
            Self::from_str(map_str_bytes, map_size)
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
    impl Drop for Win32ShMem {
        fn drop(&mut self) {
            unsafe {
                UnmapViewOfFile(self.map as *mut c_void);
                CloseHandle(self.handle);
            }
        }
    }

    impl Win32ShMem {
        pub fn from_str(map_str_bytes: &[u8; 20], map_size: usize) -> Result<Self, Error> {
            unsafe {
                let handle = OpenFileMappingA(
                    FILE_MAP_ALL_ACCESS,
                    BOOL(0),
                    PSTR(map_str_bytes as *const u8 as *mut u8),
                );
                if handle == HANDLE(0) {
                    return Err(Error::Unknown(format!(
                        "Cannot open shared memory {}",
                        String::from_utf8_lossy(map_str_bytes)
                    )));
                }
                let map =
                    MapViewOfFile(handle.clone(), FILE_MAP_ALL_ACCESS, 0, 0, map_size) as *mut u8;
                if map == ptr::null_mut() {
                    return Err(Error::Unknown(format!(
                        "Cannot map shared memory {}",
                        String::from_utf8_lossy(map_str_bytes)
                    )));
                }
                let mut ret = Self {
                    shm_str: [0; 20],
                    handle: handle,
                    map: map,
                    map_size: map_size,
                };
                ret.shm_str.clone_from_slice(map_str_bytes);
                Ok(ret)
            }
        }

        pub fn new(map_size: usize) -> Result<Self, Error> {
            unsafe {
                let uuid = Uuid::new_v4();
                let mut map_str = format!("libafl_{}", uuid.to_simple());
                let map_str_bytes = map_str.as_mut_vec();
                map_str_bytes[19] = 0; // Trucate to size 20
                let handle = CreateFileMappingA(
                    HANDLE(INVALID_HANDLE_VALUE),
                    ptr::null_mut(),
                    PAGE_TYPE::PAGE_READWRITE,
                    0,
                    map_size as u32,
                    PSTR(map_str_bytes.as_mut_ptr()),
                );
                if handle == HANDLE(0) {
                    return Err(Error::Unknown(format!(
                        "Cannot create shared memory {}",
                        String::from_utf8_lossy(map_str_bytes)
                    )));
                }
                let map =
                    MapViewOfFile(handle.clone(), FILE_MAP_ALL_ACCESS, 0, 0, map_size) as *mut u8;
                if map == ptr::null_mut() {
                    return Err(Error::Unknown(format!(
                        "Cannot map shared memory {}",
                        String::from_utf8_lossy(map_str_bytes)
                    )));
                }
                let mut ret = Self {
                    shm_str: [0; 20],
                    handle: handle,
                    map: map,
                    map_size: map_size,
                };
                ret.shm_str.clone_from_slice(&map_str_bytes[0..20]);
                Ok(ret)
            }
        }
    }
}

#[cfg(test)]
mod tests {

    #[cfg(all(unix, feature = "std"))]
    use super::{ShMem, UnixShMem};

    #[cfg(all(unix, feature = "std"))]
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
