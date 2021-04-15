//! A generic sharememory region to be used by any functions (queues or feedbacks
// too.)

#[cfg(all(feature = "std", unix))]
pub use unix_shmem::{UnixShMemMapping, UnixShMemProvider};
#[cfg(all(feature = "std", unix))]
pub type StdShMemProvider = UnixShMemProvider;
#[cfg(all(feature = "std", unix))]
pub type StdShMemMapping = UnixShMemMapping;

#[cfg(all(windows, feature = "std"))]
pub use win32_shmem::{Win32ShMemMapping, Win32ShMemProvider};
#[cfg(all(windows, feature = "std"))]
pub type StdShMemProvider = Win32ShMemProvider;
#[cfg(all(windows, feature = "std"))]
pub type StdShMemMapping = Win32ShMemMapping;

use core::fmt::Debug;
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::{env, num::ParseIntError};

use crate::Error;

/// Description of a shared map.
/// May be used to restore the map by id.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct ShMemDescription {
    /// Size of this map
    pub size: usize,
    /// Id of this map
    pub id: ShMemId,
}

impl ShMemDescription {
    pub fn from_string_and_size(string: &str, size: usize) -> Self {
        Self {
            size,
            id: ShMemId::from_string(string),
        }
    }
}

/// An id associated with a given shared memory mapping (ShMemMapping), which can be used to
/// establish shared-mappings between proccesses.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub struct ShMemId {
    id: [u8; 20],
}

impl ShMemId {
    /// Create a new id from a fixed-size string
    pub fn from_slice(slice: &[u8; 20]) -> Self {
        Self { id: *slice }
    }

    /// Create a new id from an int
    pub fn from_int(val: i32) -> Self {
        let mut slice: [u8; 20] = [0; 20];
        let bytes = val.to_be_bytes();
        let start_pos = bytes.iter().position(|&c| c != 0).unwrap();
        for (i, val) in bytes[start_pos..].iter().enumerate() {
            slice[i] = *val;
        }
        Self { id: slice }
    }

    /// Create a new id from a string
    pub fn from_string(val: &str) -> Self {
        let mut slice: [u8; 20] = [0; 20];
        for (i, val) in val.as_bytes().iter().enumerate() {
            slice[i] = *val;
        }
        Self { id: slice }
    }

    /// Get the id as a fixed-length slice
    pub fn as_slice(&self) -> &[u8; 20] {
        &self.id
    }

    /// Get a string representation of this id
    pub fn to_string(&self) -> &str {
        let eof_pos = self.id.iter().position(|&c| c == 0).unwrap();
        alloc::str::from_utf8(&self.id[..eof_pos]).unwrap()
    }

    /// Get an integer representation of this id
    pub fn to_int(&self) -> Result<i32, ParseIntError> {
        self.to_string().parse()
    }
}

pub trait ShMemMapping: Sized + Debug + Send + Clone {
    /// Get the id of this shared memory mapping
    fn id(&self) -> ShMemId;

    /// Get the size of this mapping
    fn len(&self) -> usize;

    /// Check if the mapping is empty
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the description of the shared memory mapping
    fn description(&self) -> ShMemDescription {
        ShMemDescription {
            size: self.len(),
            id: self.id(),
        }
    }

    /// The actual shared map, in memory
    fn map(&self) -> &[u8];

    /// The actual shared map, mutable
    fn map_mut(&mut self) -> &mut [u8];
    ///
    /// Write this map's config to env
    #[cfg(feature = "std")]
    fn write_to_env(&self, env_name: &str) -> Result<(), Error> {
        let map_size = self.len();
        let map_size_env = format!("{}_SIZE", env_name);
        env::set_var(env_name, self.id().to_string());
        env::set_var(map_size_env, format!("{}", map_size));
        Ok(())
    }
}

pub trait ShMemProvider: Send {
    type Mapping: ShMemMapping;

    /// Create a new shared memory mapping
    fn new_map(&mut self, map_size: usize) -> Result<Self::Mapping, Error>;

    /// Get a mapping given its id and size
    fn from_id_and_size(&mut self, id: ShMemId, size: usize) -> Result<Self::Mapping, Error>;

    /// Get a mapping given a description
    fn from_description(&mut self, description: ShMemDescription) -> Result<Self::Mapping, Error> {
        self.from_id_and_size(description.id, description.size)
    }

    fn clone_ref(&mut self, mapping: &Self::Mapping) -> Result<Self::Mapping, Error> {
        self.from_id_and_size(mapping.id(), mapping.len())
    }

    /// Reads an existing map config from env vars, then maps it
    #[cfg(feature = "std")]
    fn from_env(&mut self, env_name: &str) -> Result<Self::Mapping, Error> {
        let map_shm_str = env::var(env_name)?;
        let map_size = str::parse::<usize>(&env::var(format!("{}_SIZE", env_name))?)?;
        self.from_description(ShMemDescription::from_string_and_size(
            &map_shm_str,
            map_size,
        ))
    }
}

#[cfg(all(unix, feature = "std"))]
pub mod unix_shmem {

    #[cfg(target_os = "android")]
    pub type UnixShMemProvider = ashmem::AshmemShMemProvider;
    #[cfg(target_os = "android")]
    pub type UnixShMemMapping = ashmem::AshmemShMemMapping;
    #[cfg(not(target_os = "android"))]
    pub type UnixShMemProvider = default::DefaultUnixShMemProvider;
    #[cfg(not(target_os = "android"))]
    pub type UnixShMemMapping = ashmem::AshmemShMemMapping;

    #[cfg(all(unix, feature = "std", not(target_os = "android")))]
    mod default {
        use core::{ptr, slice};
        use libc::{c_int, c_long, c_uchar, c_uint, c_ulong, c_ushort, c_void};

        use crate::Error;

        use super::super::{ShMemId, ShMemMapping, ShMemProvider};

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

        extern "C" {
            fn shmctl(__shmid: c_int, __cmd: c_int, __buf: *mut shmid_ds) -> c_int;
            fn shmget(__key: c_int, __size: c_ulong, __shmflg: c_int) -> c_int;
            fn shmat(__shmid: c_int, __shmaddr: *const c_void, __shmflg: c_int) -> *mut c_void;
        }

        /// The default sharedmap impl for unix using shmctl & shmget
        #[derive(Clone, Debug)]
        pub struct DefaultUnixShMemMapping {
            id: ShMemId,
            map: *mut u8,
            map_size: usize,
        }

        unsafe impl Send for DefaultUnixShMemMapping {}

        impl DefaultUnixShMemMapping {
            /// Create a new shared memory mapping, using shmget/shmat
            pub fn new(map_size: usize) -> Result<Self, Error> {
                unsafe {
                    let os_id = shmget(
                        0,
                        map_size as c_ulong,
                        0o1000 | 0o2000 | 0o600,
                    );

                    if os_id < 0_i32 {
                        return Err(Error::Unknown(format!("Failed to allocate a shared mapping of size {} - check OS limits (i.e shmall, shmmax)", map_size)))
                    }

                    let map = shmat(os_id, ptr::null(), 0) as *mut c_uchar;

                    if map == usize::MAX as c_int as *mut c_void as *mut c_uchar || map.is_null() {
                        shmctl(os_id, 0, ptr::null_mut());
                        return Err(Error::Unknown("Failed to map the shared mapping".to_string()));
                    }

                    Ok(Self {
                        id: ShMemId::from_int(os_id),
                        map,
                        map_size,
                    })
                }
            }

            /// Get a UnixShMemMapping of the existing shared memory mapping identified by id
            pub fn from_id_and_size(id: ShMemId, map_size: usize) -> Result<Self, Error> {
                unsafe {
                    let map = shmat(id.to_int().unwrap(), ptr::null(), 0) as *mut c_uchar;

                    if map == usize::MAX as *mut c_void as *mut c_uchar || map.is_null() {
                        return Err(Error::Unknown("Failed to map the shared mapping".to_string()));
                    }

                    Ok(Self { id, map, map_size })
                }
            }
        }

        #[cfg(unix)]
        impl ShMemMapping for DefaultUnixShMemMapping {
            fn id(&self) -> ShMemId {
                self.id
            }

            fn len(&self) -> usize {
                self.map_size
            }

            fn map(&self) -> &[u8] {
                unsafe { slice::from_raw_parts(self.map, self.map_size) }
            }

            fn map_mut(&mut self) -> &mut [u8] {
                unsafe { slice::from_raw_parts_mut(self.map, self.map_size) }
            }
        }

        /// Drop implementation for UnixShMemMapping, which cleans up the mapping
        #[cfg(unix)]
        impl Drop for DefaultUnixShMemMapping {
            fn drop(&mut self) {
                unsafe {
                    shmctl(self.id.to_int().unwrap(), 0, ptr::null_mut());
                }
            }
        }

        /// A ShMemProvider which uses shmget/shmat/shmctl to provide shared memory mappings.
        #[cfg(unix)]
        #[derive(Debug)]
        pub struct DefaultUnixShMemProvider {}

        unsafe impl Send for DefaultUnixShMemProvider {}

        /// Implementation for UnixShMemProvider
        #[cfg(unix)]
        impl DefaultUnixShMemProvider {
            pub fn new() -> Self {
                Self {}
            }
        }

        #[cfg(unix)]
        impl Default for DefaultUnixShMemProvider {
            fn default() -> Self {
                Self::new()
            }
        }

        /// Implement ShMemProvider for UnixShMemProvider
        #[cfg(unix)]
        impl ShMemProvider for DefaultUnixShMemProvider {
            type Mapping = DefaultUnixShMemMapping;

            fn new_map(&mut self, map_size: usize) -> Result<Self::Mapping, Error> {
                DefaultUnixShMemMapping::new(map_size)
            }

            fn from_id_and_size(
                &mut self,
                id: ShMemId,
                size: usize,
            ) -> Result<Self::Mapping, Error> {
                DefaultUnixShMemMapping::from_id_and_size(id, size)
            }
        }
    }

    #[cfg(all(unix, feature = "std"))]
    pub mod ashmem {
        use core::slice;
        use libc::{
            c_char, c_int, c_long, c_uint, c_void, off_t, size_t, MAP_SHARED, O_RDWR, PROT_READ,
            PROT_WRITE,
        };
        use std::ffi::CString;

        use crate::Error;

        use super::super::{ShMemId, ShMemMapping, ShMemProvider};

        extern "C" {
            fn ioctl(fd: c_int, request: c_long, ...) -> c_int;
            fn open(path: *const c_char, oflag: c_int, ...) -> c_int;
            fn close(fd: c_int) -> c_int;
            fn mmap(
                addr: *mut c_void,
                len: size_t,
                prot: c_int,
                flags: c_int,
                fd: c_int,
                offset: off_t,
            ) -> *mut c_void;

        }

        /// An ashmem based impl for linux/android
        #[cfg(unix)]
        #[derive(Clone, Debug)]
        pub struct AshmemShMemMapping {
            id: ShMemId,
            map: *mut u8,
            map_size: usize,
        }

        unsafe impl Send for AshmemShMemMapping {}

        #[derive(Copy, Clone)]
        #[repr(C)]
        struct ashmem_pin {
            pub offset: c_uint,
            pub len: c_uint,
        }

        const ASHMEM_GET_SIZE: c_long = 0x00007704;
        const ASHMEM_UNPIN: c_long = 0x40087708;
        //const ASHMEM_SET_NAME: c_long = 0x41007701;
        const ASHMEM_SET_SIZE: c_long = 0x40087703;

        impl AshmemShMemMapping {
            /// Create a new shared memory mapping, using shmget/shmat
            pub fn new(map_size: usize) -> Result<Self, Error> {
                unsafe {
                    let device_path = CString::new(
                        if let Ok(boot_id) =
                            std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                        {
                            format!("{}{}", "/dev/ashmem", boot_id).trim().to_string()
                        } else {
                            "/dev/ashmem".to_string()
                        },
                    )
                    .unwrap();

                    let fd = open(device_path.as_ptr(), O_RDWR);
                    if fd == -1 {
                        return Err(Error::Unknown(format!(
                            "Failed to open the ashmem device at {:?}",
                            device_path
                        )));
                    }

                    //if ioctl(fd, ASHMEM_SET_NAME, name) != 0 {
                    //close(fd);
                    //return Err(Error::Unknown("Failed to set the ashmem mapping's name".to_string()));
                    //};

                    if ioctl(fd, ASHMEM_SET_SIZE, map_size) != 0 {
                        close(fd);
                        return Err(Error::Unknown(
                            "Failed to set the ashmem mapping's size".to_string(),
                        ));
                    };

                    let map = mmap(
                        std::ptr::null_mut(),
                        map_size,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED,
                        fd,
                        0,
                    );
                    if map == usize::MAX as *mut c_void {
                        close(fd);
                        return Err(Error::Unknown(
                            "Failed to map the ashmem mapping".to_string(),
                        ));
                    }

                    Ok(Self {
                        id: ShMemId::from_string(&format!("{}", fd)),
                        map: map as *mut u8,
                        map_size,
                    })
                }
            }

            /// Get a UnixShMemMapping of the existing shared memory mapping identified by id
            pub fn from_id_and_size(id: ShMemId, map_size: usize) -> Result<Self, Error> {
                unsafe {
                    let fd: i32 = id.to_string().parse().unwrap();
                    if ioctl(fd, ASHMEM_GET_SIZE) != map_size as i32 {
                        return Err(Error::Unknown(
                            "The mapping's size differs from the requested size".to_string(),
                        ));
                    };

                    let map = mmap(
                        std::ptr::null_mut(),
                        map_size,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED,
                        fd,
                        0,
                    );
                    if map == usize::MAX as *mut c_void {
                        close(fd);
                        return Err(Error::Unknown(
                            "Failed to map the ashmem mapping".to_string(),
                        ));
                    }

                    Ok(Self {
                        id,
                        map: map as *mut u8,
                        map_size,
                    })
                }
            }

            ///// Get the file descriptor from an AshmemShMemMapping's id
            //pub fn fd_from_id(id: ShMemId) -> Result<c_int, Error> {
            //let result = if let Some(fd_str) = id.to_string().split(":").collect::<Vec<&str>>().get(1) {
            //println!("id: {}, fd_str: {}", id.to_string(), fd_str);
            //Ok(fd_str.parse().expect("Could not parse the file descriptor"))
            //} else {
            //Err(Error::Unknown("Invalid id for ashmem".to_string()))
            //};
            //result
            //}
        }

        #[cfg(unix)]
        impl ShMemMapping for AshmemShMemMapping {
            fn id(&self) -> ShMemId {
                self.id
            }

            fn len(&self) -> usize {
                self.map_size
            }

            fn map(&self) -> &[u8] {
                unsafe { slice::from_raw_parts(self.map, self.map_size) }
            }

            fn map_mut(&mut self) -> &mut [u8] {
                unsafe { slice::from_raw_parts_mut(self.map, self.map_size) }
            }
        }

        /// Drop implementation for AshmemShMemMapping, which cleans up the mapping
        #[cfg(unix)]
        impl Drop for AshmemShMemMapping {
            fn drop(&mut self) {
                unsafe {
                    //let fd = Self::fd_from_id(self.id).unwrap();
                    let fd: i32 = self.id.to_string().parse().unwrap();

                    let length = ioctl(fd, ASHMEM_GET_SIZE);

                    let ap = ashmem_pin {
                        offset: 0,
                        len: length as u32,
                    };

                    ioctl(fd, ASHMEM_UNPIN, &ap);
                    close(fd);
                }
            }
        }

        /// A ShMemProvider which uses shmget/shmat/shmctl to provide shared memory mappings.
        #[cfg(unix)]
        #[derive(Debug)]
        pub struct AshmemShMemProvider {}

        unsafe impl Send for AshmemShMemProvider {}

        /// Implementation for AshmemShMemProvider
        #[cfg(unix)]
        impl AshmemShMemProvider {
            pub fn new() -> Self {
                Self {}
            }
        }

        #[cfg(unix)]
        impl Default for AshmemShMemProvider {
            fn default() -> Self {
                Self::new()
            }
        }

        /// Implement ShMemProvider for AshmemShMemProvider
        #[cfg(unix)]
        impl ShMemProvider for AshmemShMemProvider {
            type Mapping = AshmemShMemMapping;

            fn new_map(&mut self, map_size: usize) -> Result<Self::Mapping, Error> {
                let mapping = AshmemShMemMapping::new(map_size)?;
                Ok(mapping)
            }

            fn from_id_and_size(
                &mut self,
                id: ShMemId,
                size: usize,
            ) -> Result<Self::Mapping, Error> {
                AshmemShMemMapping::from_id_and_size(id, size)
            }
        }
    }
}

#[cfg(all(feature = "std", windows))]
pub mod win32_shmem {

    use super::{ShMemId, ShMemMapping, ShMemProvider};
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
    pub struct Win32ShMemMapping {
        id: ShMemId,
        handle: HANDLE,
        map: *mut u8,
        map_size: usize,
    }

    impl Win32ShMemMapping {
        fn new_map(map_size: usize) -> Result<Self, Error> {
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
                let map = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, map_size) as *mut u8;
                if map == ptr::null_mut() {
                    return Err(Error::Unknown(format!(
                        "Cannot map shared memory {}",
                        String::from_utf8_lossy(map_str_bytes)
                    )));
                }

                Ok(Self {
                    id: ShMemId::from_string(&map_str_bytes[0..20]),
                    handle,
                    map,
                    map_size,
                })
            }
        }

        fn from_id_and_size(id: ShMemId, map_size: usize) -> Result<Self, Error> {
            unsafe {
                let map_str_bytes = id.id;

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
                let map = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, map_size) as *mut u8;
                if map.is_null() {
                    return Err(Error::Unknown(format!(
                        "Cannot map shared memory {}",
                        String::from_utf8_lossy(map_str_bytes)
                    )));
                }
                Ok(Self {
                    id,
                    handle,
                    map,
                    map_size,
                })
            }
        }
    }

    impl ShMemMapping for Win32ShMemMapping {
        fn id(&self) -> ShMemId {
            self.id
        }

        fn len(&self) -> usize {
            self.map_size
        }

        fn map(&self) -> &[u8] {
            unsafe { slice::from_raw_parts(self.map, self.map_size) }
        }

        fn map_mut(&mut self) -> &mut [u8] {
            unsafe { slice::from_raw_parts_mut(self.map, self.map_size) }
        }
    }

    /// Deinit sharedmaps on drop
    impl Drop for Win32ShMemMapping {
        fn drop(&mut self) {
            unsafe {
                UnmapViewOfFile(self.map as *mut c_void);
                CloseHandle(self.handle);
            }
        }
    }

    /// A ShMemProvider which uses win32 functions to provide shared memory mappings.
    #[derive(Debug)]
    pub struct Win32ShMemProvider {}

    /// Implementation for Win32ShMemProvider
    impl Win32ShMemProvider {
        pub fn new() -> Self {
            Self {}
        }
    }

    /// Implement ShMemProvider for Win32ShMemProvider
    impl ShMemProvider for Win32ShMemProvider {
        fn new_map(&mut self, map_size: usize) -> Result<&mut Self::Mapping, Error> {
            Win32ShMemMapping::new(map_size)
        }

        fn from_id_and_size(
            &mut self,
            id: ShMemId,
            size: usize,
        ) -> Result<&mut Self::Mapping, Error> {
            Win32ShMemMapping::from_id_and_size(id, size)
        }
    }
}
