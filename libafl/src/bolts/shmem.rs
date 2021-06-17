//! A generic sharememory region to be used by any functions (queues or feedbacks
// too.)

#[cfg(all(feature = "std", unix))]
pub use unix_shmem::{UnixShMem, UnixShMemProvider};
/// The default [`ShMemProvider`] for this os.
#[cfg(all(feature = "std", unix))]
pub type OsShMemProvider = UnixShMemProvider;
/// The default [`ShMem`] for this os.
#[cfg(all(feature = "std", unix))]
pub type OsShMem = UnixShMem;

#[cfg(all(windows, feature = "std"))]
pub use win32_shmem::{Win32ShMem, Win32ShMemProvider};
#[cfg(all(windows, feature = "std"))]
pub type OsShMemProvider = Win32ShMemProvider;
#[cfg(all(windows, feature = "std"))]
pub type OsShMem = Win32ShMem;

use crate::Error;

#[cfg(all(target_os = "android", feature = "std"))]
use crate::bolts::os::ashmem_server::ServedShMemProvider;
#[cfg(all(target_os = "android", feature = "std"))]
pub type StdShMemProvider = RcShMemProvider<ServedShMemProvider>;
#[cfg(all(target_os = "android", feature = "std"))]
pub type StdShMem = RcShMem<ServedShMemProvider>;

/// The default [`ShMemProvider`] for this os.
#[cfg(all(feature = "std", not(target_os = "android")))]
pub type StdShMemProvider = OsShMemProvider;
/// The default [`ShMem`] for this os.
#[cfg(all(feature = "std", not(target_os = "android")))]
pub type StdShMem = OsShMem;

use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::env;

use alloc::{rc::Rc, string::ToString};
use core::{cell::RefCell, fmt::Debug, mem::ManuallyDrop};

#[cfg(all(unix, feature = "std"))]
use crate::bolts::os::pipes::Pipe;
#[cfg(all(unix, feature = "std"))]
use std::io::{Read, Write};

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
    /// Create a description from a `id_str` and a `size`.
    #[must_use]
    pub fn from_string_and_size(id_str: &str, size: usize) -> Self {
        Self {
            size,
            id: ShMemId::from_string(id_str),
        }
    }
}

/// An id associated with a given shared memory mapping ([`ShMem`]), which can be used to
/// establish shared-mappings between proccesses.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub struct ShMemId {
    id: [u8; 20],
}

impl ShMemId {
    /// Create a new id from a fixed-size string
    #[must_use]
    pub fn from_slice(slice: &[u8; 20]) -> Self {
        Self { id: *slice }
    }

    /// Create a new id from an int
    #[must_use]
    pub fn from_int(val: i32) -> Self {
        Self::from_string(&val.to_string())
    }

    /// Create a new id from a string
    #[must_use]
    pub fn from_string(val: &str) -> Self {
        let mut slice: [u8; 20] = [0; 20];
        for (i, val) in val.as_bytes().iter().enumerate() {
            slice[i] = *val;
        }
        Self { id: slice }
    }

    /// Get the id as a fixed-length slice
    #[must_use]
    pub fn as_slice(&self) -> &[u8; 20] {
        &self.id
    }

    /// Get a string representation of this id
    #[must_use]
    pub fn to_string(&self) -> &str {
        let eof_pos = self.id.iter().position(|&c| c == 0).unwrap();
        alloc::str::from_utf8(&self.id[..eof_pos]).unwrap()
    }

    /// Get an integer representation of this id
    #[must_use]
    pub fn to_int(&self) -> i32 {
        let id: i32 = self.to_string().parse().unwrap();
        id
    }
}

/// A [`ShMem`] is an interface to shared maps.
/// They are the backbone of [`crate::bolts::llmp`] for inter-process communication.
/// All you need for scaling on a new target is to implement this interface, as well as the respective [`ShMemProvider`].
pub trait ShMem: Sized + Debug + Clone {
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

/// A [`ShMemProvider`] provides access to shared maps.
/// They are the backbone of [`crate::bolts::llmp`] for inter-process communication.
/// All you need for scaling on a new target is to implement this interface, as well as the respective [`ShMem`].
pub trait ShMemProvider: Send + Clone + Default + Debug {
    /// The actual shared map handed out by this [`ShMemProvider`].
    type Mem: ShMem;

    /// Create a new instance of the provider
    fn new() -> Result<Self, Error>;

    /// Create a new shared memory mapping
    fn new_map(&mut self, map_size: usize) -> Result<Self::Mem, Error>;

    /// Get a mapping given its id and size
    fn from_id_and_size(&mut self, id: ShMemId, size: usize) -> Result<Self::Mem, Error>;

    /// Get a mapping given a description
    fn from_description(&mut self, description: ShMemDescription) -> Result<Self::Mem, Error> {
        self.from_id_and_size(description.id, description.size)
    }

    /// Create a new sharedmap reference from an existing `id` and `len`
    fn clone_ref(&mut self, mapping: &Self::Mem) -> Result<Self::Mem, Error> {
        self.from_id_and_size(mapping.id(), mapping.len())
    }

    /// Reads an existing map config from env vars, then maps it
    #[cfg(feature = "std")]
    fn existing_from_env(&mut self, env_name: &str) -> Result<Self::Mem, Error> {
        let map_shm_str = env::var(env_name)?;
        let map_size = str::parse::<usize>(&env::var(format!("{}_SIZE", env_name))?)?;
        self.from_description(ShMemDescription::from_string_and_size(
            &map_shm_str,
            map_size,
        ))
    }

    /// This method should be called before a fork or a thread creation event, allowing the [`ShMemProvider`] to
    /// get ready for a potential reset of thread specific info, and for potential reconnects.
    /// Make sure to call [`Self::post_fork()`] after threading!
    fn pre_fork(&mut self) -> Result<(), Error> {
        // do nothing
        Ok(())
    }

    /// This method should be called after a fork or after cloning/a thread creation event, allowing the [`ShMemProvider`] to
    /// reset thread specific info, and potentially reconnect.
    /// Make sure to call [`Self::pre_fork()`] before threading!
    fn post_fork(&mut self, _is_child: bool) -> Result<(), Error> {
        // do nothing
        Ok(())
    }

    /// Release the resources associated with the given [`ShMem`]
    fn release_map(&mut self, _map: &mut Self::Mem) {
        // do nothing
    }
}

/// A Refernce Counted shared map,
/// that can use internal mutability.
/// Useful if the `ShMemProvider` needs to keep local state.
#[derive(Debug, Clone)]
pub struct RcShMem<T: ShMemProvider> {
    internal: ManuallyDrop<T::Mem>,
    provider: Rc<RefCell<T>>,
}

impl<T> ShMem for RcShMem<T>
where
    T: ShMemProvider + alloc::fmt::Debug,
{
    fn id(&self) -> ShMemId {
        self.internal.id()
    }

    fn len(&self) -> usize {
        self.internal.len()
    }

    fn map(&self) -> &[u8] {
        self.internal.map()
    }

    fn map_mut(&mut self) -> &mut [u8] {
        self.internal.map_mut()
    }
}

impl<T: ShMemProvider> Drop for RcShMem<T> {
    fn drop(&mut self) {
        self.provider.borrow_mut().release_map(&mut self.internal);
    }
}

/// A Refernce Counted `ShMemProvider`,
/// that can use internal mutability.
/// Useful if the `ShMemProvider` needs to keep local state.
#[derive(Debug, Clone)]
#[cfg(all(unix, feature = "std"))]
pub struct RcShMemProvider<T: ShMemProvider> {
    /// The wrapped [`ShMemProvider`].
    internal: Rc<RefCell<T>>,
    /// A pipe the child uses to communicate progress to the parent after fork.
    /// This prevents a potential race condition when using the [`AshmemService`].
    #[cfg(unix)]
    child_parent_pipe: Option<Pipe>,
    #[cfg(unix)]
    /// A pipe the parent uses to communicate progress to the child after fork.
    /// This prevents a potential race condition when using the [`AshmemService`].
    parent_child_pipe: Option<Pipe>,
}

#[cfg(all(unix, feature = "std"))]
unsafe impl<T: ShMemProvider> Send for RcShMemProvider<T> {}

#[cfg(all(unix, feature = "std"))]
impl<T> ShMemProvider for RcShMemProvider<T>
where
    T: ShMemProvider + alloc::fmt::Debug,
{
    type Mem = RcShMem<T>;

    fn new() -> Result<Self, Error> {
        Ok(Self {
            internal: Rc::new(RefCell::new(T::new()?)),
            child_parent_pipe: None,
            parent_child_pipe: None,
        })
    }

    fn new_map(&mut self, map_size: usize) -> Result<Self::Mem, Error> {
        Ok(Self::Mem {
            internal: ManuallyDrop::new(self.internal.borrow_mut().new_map(map_size)?),
            provider: self.internal.clone(),
        })
    }

    fn from_id_and_size(&mut self, id: ShMemId, size: usize) -> Result<Self::Mem, Error> {
        Ok(Self::Mem {
            internal: ManuallyDrop::new(self.internal.borrow_mut().from_id_and_size(id, size)?),
            provider: self.internal.clone(),
        })
    }

    fn release_map(&mut self, map: &mut Self::Mem) {
        self.internal.borrow_mut().release_map(&mut map.internal);
    }

    fn clone_ref(&mut self, mapping: &Self::Mem) -> Result<Self::Mem, Error> {
        Ok(Self::Mem {
            internal: ManuallyDrop::new(self.internal.borrow_mut().clone_ref(&mapping.internal)?),
            provider: self.internal.clone(),
        })
    }

    /// This method should be called before a fork or a thread creation event, allowing the [`ShMemProvider`] to
    /// get ready for a potential reset of thread specific info, and for potential reconnects.
    fn pre_fork(&mut self) -> Result<(), Error> {
        // Set up the pipes to communicate progress over, later.
        self.child_parent_pipe = Some(Pipe::new()?);
        self.parent_child_pipe = Some(Pipe::new()?);
        self.internal.borrow_mut().pre_fork()
    }

    /// After fork, make sure everything gets set up correctly internally.
    fn post_fork(&mut self, is_child: bool) -> Result<(), Error> {
        if is_child {
            self.await_parent_done()?;
            let child_shmem = self.internal.borrow_mut().clone();
            self.internal = Rc::new(RefCell::new(child_shmem));
        }
        self.internal.borrow_mut().post_fork(is_child)?;
        if is_child {
            self.set_child_done()?;
        } else {
            self.set_parent_done()?;
            self.await_child_done()?;
        }

        self.parent_child_pipe = None;
        self.child_parent_pipe = None;
        Ok(())
    }
}

#[cfg(all(unix, feature = "std"))]
impl<T> RcShMemProvider<T>
where
    T: ShMemProvider,
{
    /// "set" the "latch"
    /// (we abuse `pipes` as `semaphores`, as they don't need an additional shared mem region.)
    fn pipe_set(pipe: &mut Option<Pipe>) -> Result<(), Error> {
        match pipe {
            Some(pipe) => {
                let ok = [0u8; 4];
                pipe.write_all(&ok)?;
                Ok(())
            }
            None => Err(Error::IllegalState(
                "Unexpected `None` Pipe in RcShMemProvider! Missing post_fork()?".to_string(),
            )),
        }
    }

    /// "await" the "latch"
    fn pipe_await(pipe: &mut Option<Pipe>) -> Result<(), Error> {
        match pipe {
            Some(pipe) => {
                let ok = [0u8; 4];
                let mut ret = ok;
                pipe.read_exact(&mut ret)?;
                if ret == ok {
                    Ok(())
                } else {
                    Err(Error::Unknown(format!(
                        "Wrong result read from pipe! Expected 0, got {:?}",
                        ret
                    )))
                }
            }
            None => Err(Error::IllegalState(
                "Unexpected `None` Pipe in RcShMemProvider! Missing post_fork()?".to_string(),
            )),
        }
    }

    /// After fork, wait for the parent to write to our pipe :)
    fn await_parent_done(&mut self) -> Result<(), Error> {
        Self::pipe_await(&mut self.parent_child_pipe)
    }

    /// After fork, inform the new child we're done
    fn set_parent_done(&mut self) -> Result<(), Error> {
        Self::pipe_set(&mut self.parent_child_pipe)
    }

    /// After fork, wait for the child to write to our pipe :)
    fn await_child_done(&mut self) -> Result<(), Error> {
        Self::pipe_await(&mut self.child_parent_pipe)
    }

    /// After fork, inform the new child we're done
    fn set_child_done(&mut self) -> Result<(), Error> {
        Self::pipe_set(&mut self.child_parent_pipe)
    }
}

#[cfg(all(unix, feature = "std"))]
impl<T> Default for RcShMemProvider<T>
where
    T: ShMemProvider + alloc::fmt::Debug,
{
    fn default() -> Self {
        Self::new().unwrap()
    }
}

/// A Unix sharedmem implementation.
///
/// On Android, this is partially reused to wrap [`unix_shmem::ashmem::AshmemShMem`],
/// Although for an [`unix_shmem::ashmem::AshmemShMemProvider`] using a unix domain socket
/// Is needed on top.
#[cfg(all(unix, feature = "std"))]
pub mod unix_shmem {

    /// Shared memory provider for Android, allocating and forwarding maps over unix domain sockets.
    #[cfg(target_os = "android")]
    pub type UnixShMemProvider = ashmem::AshmemShMemProvider;
    /// Shared memory for Android
    #[cfg(target_os = "android")]
    pub type UnixShMem = ashmem::AshmemShMem;
    /// Shared memory Provider for Unix
    #[cfg(not(target_os = "android"))]
    pub type UnixShMemProvider = default::CommonUnixShMemProvider;
    /// Shared memory for Unix
    #[cfg(not(target_os = "android"))]
    pub type UnixShMem = ashmem::AshmemShMem;

    #[cfg(all(unix, feature = "std", not(target_os = "android")))]
    mod default {
        use core::{ptr, slice};
        use libc::{c_int, c_long, c_uchar, c_uint, c_ulong, c_ushort, c_void};

        use crate::{
            bolts::shmem::{ShMem, ShMemId, ShMemProvider},
            Error,
        };
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
        pub struct CommonUnixShMem {
            id: ShMemId,
            map: *mut u8,
            map_size: usize,
        }

        impl CommonUnixShMem {
            /// Create a new shared memory mapping, using shmget/shmat
            pub fn new(map_size: usize) -> Result<Self, Error> {
                unsafe {
                    let os_id = shmget(0, map_size as c_ulong, 0o1000 | 0o2000 | 0o600);

                    if os_id < 0_i32 {
                        return Err(Error::Unknown(format!("Failed to allocate a shared mapping of size {} - check OS limits (i.e shmall, shmmax)", map_size)));
                    }

                    let map = shmat(os_id, ptr::null(), 0) as *mut c_uchar;

                    if map as c_int == -1 || map.is_null() {
                        shmctl(os_id, 0, ptr::null_mut());
                        return Err(Error::Unknown(
                            "Failed to map the shared mapping".to_string(),
                        ));
                    }

                    Ok(Self {
                        id: ShMemId::from_int(os_id),
                        map,
                        map_size,
                    })
                }
            }

            /// Get a [`UnixShMem`] of the existing shared memory mapping identified by id
            pub fn from_id_and_size(id: ShMemId, map_size: usize) -> Result<Self, Error> {
                unsafe {
                    let map = shmat(id.to_int(), ptr::null(), 0) as *mut c_uchar;

                    if map == usize::MAX as *mut c_void as *mut c_uchar || map.is_null() {
                        return Err(Error::Unknown(
                            "Failed to map the shared mapping".to_string(),
                        ));
                    }

                    Ok(Self { id, map, map_size })
                }
            }
        }

        #[cfg(unix)]
        impl ShMem for CommonUnixShMem {
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

        /// [`Drop`] implementation for [`UnixShMem`], which cleans up the mapping.
        #[cfg(unix)]
        impl Drop for CommonUnixShMem {
            fn drop(&mut self) {
                unsafe {
                    shmctl(self.id.to_int(), 0, ptr::null_mut());
                }
            }
        }

        /// A [`ShMemProvider`] which uses `shmget`/`shmat`/`shmctl` to provide shared memory mappings.
        #[cfg(unix)]
        #[derive(Clone, Debug)]
        pub struct CommonUnixShMemProvider {}

        unsafe impl Send for CommonUnixShMemProvider {}

        #[cfg(unix)]
        impl Default for CommonUnixShMemProvider {
            fn default() -> Self {
                Self::new().unwrap()
            }
        }

        /// Implement [`ShMemProvider`] for [`UnixShMemProvider`].
        #[cfg(unix)]
        impl ShMemProvider for CommonUnixShMemProvider {
            type Mem = CommonUnixShMem;

            fn new() -> Result<Self, Error> {
                Ok(Self {})
            }
            fn new_map(&mut self, map_size: usize) -> Result<Self::Mem, Error> {
                CommonUnixShMem::new(map_size)
            }

            fn from_id_and_size(&mut self, id: ShMemId, size: usize) -> Result<Self::Mem, Error> {
                CommonUnixShMem::from_id_and_size(id, size)
            }
        }
    }

    /// Module containing `ashmem` shared memory support, commonly used on Android.
    #[cfg(all(unix, feature = "std"))]
    pub mod ashmem {
        use core::slice;
        use libc::{
            c_char, c_int, c_long, c_uint, c_void, off_t, size_t, MAP_SHARED, O_RDWR, PROT_READ,
            PROT_WRITE,
        };
        use std::ffi::CString;

        use crate::{
            bolts::shmem::{ShMem, ShMemId, ShMemProvider},
            Error,
        };

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
        pub struct AshmemShMem {
            id: ShMemId,
            map: *mut u8,
            map_size: usize,
        }

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

        impl AshmemShMem {
            /// Create a new shared memory mapping, using shmget/shmat
            pub fn new(map_size: usize) -> Result<Self, Error> {
                unsafe {
                    let device_path = CString::new(
                        if let Ok(boot_id) =
                            std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                        {
                            let path_str =
                                format!("{}{}", "/dev/ashmem", boot_id).trim().to_string();
                            if std::path::Path::new(&path_str).exists() {
                                path_str
                            } else {
                                "/dev/ashmem".to_string()
                            }
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

            /// Get a [`crate::bolts::shmem::unix_shmem::UnixShMem`] of the existing [`ShMem`] mapping identified by id.
            pub fn from_id_and_size(id: ShMemId, map_size: usize) -> Result<Self, Error> {
                unsafe {
                    let fd: i32 = id.to_string().parse().unwrap();
                    #[allow(clippy::cast_sign_loss)]
                    if ioctl(fd, ASHMEM_GET_SIZE) as u32 as usize != map_size {
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
        }

        #[cfg(unix)]
        impl ShMem for AshmemShMem {
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

        /// [`Drop`] implementation for [`AshmemShMem`], which cleans up the mapping.
        #[cfg(unix)]
        impl Drop for AshmemShMem {
            fn drop(&mut self) {
                unsafe {
                    let fd: i32 = self.id.to_string().parse().unwrap();

                    #[allow(clippy::cast_sign_loss)]
                    let length = ioctl(fd, ASHMEM_GET_SIZE) as u32;

                    let ap = ashmem_pin {
                        offset: 0,
                        len: length,
                    };

                    ioctl(fd, ASHMEM_UNPIN, &ap);
                    close(fd);
                }
            }
        }

        /// A [`ShMemProvider`] which uses ashmem to provide shared memory mappings.
        #[cfg(unix)]
        #[derive(Clone, Debug)]
        pub struct AshmemShMemProvider {}

        unsafe impl Send for AshmemShMemProvider {}

        #[cfg(unix)]
        impl Default for AshmemShMemProvider {
            fn default() -> Self {
                Self::new().unwrap()
            }
        }

        /// Implement [`ShMemProvider`] for [`AshmemShMemProvider`], for the Android `ShMem`.
        #[cfg(unix)]
        impl ShMemProvider for AshmemShMemProvider {
            type Mem = AshmemShMem;

            fn new() -> Result<Self, Error> {
                Ok(Self {})
            }

            fn new_map(&mut self, map_size: usize) -> Result<Self::Mem, Error> {
                let mapping = AshmemShMem::new(map_size)?;
                Ok(mapping)
            }

            fn from_id_and_size(&mut self, id: ShMemId, size: usize) -> Result<Self::Mem, Error> {
                AshmemShMem::from_id_and_size(id, size)
            }
        }
    }
}

#[cfg(all(feature = "std", windows))]
pub mod win32_shmem {

    use crate::{
        bolts::{
            bindings::{
                windows::win32::system_services::{
                    CreateFileMappingA, MapViewOfFile, OpenFileMappingA, UnmapViewOfFile,
                },
                windows::win32::system_services::{BOOL, HANDLE, PAGE_TYPE, PSTR},
                windows::win32::windows_programming::CloseHandle,
            },
            shmem::{ShMem, ShMemId, ShMemProvider},
        },
        Error,
    };

    use core::{ffi::c_void, ptr, slice};
    use std::convert::TryInto;
    use uuid::Uuid;

    const INVALID_HANDLE_VALUE: isize = -1;
    const FILE_MAP_ALL_ACCESS: u32 = 0xf001f;

    /// The default Sharedmap impl for windows using shmctl & shmget
    #[derive(Clone, Debug)]
    pub struct Win32ShMem {
        id: ShMemId,
        handle: HANDLE,
        map: *mut u8,
        map_size: usize,
    }

    impl Win32ShMem {
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
                if map.is_null() {
                    return Err(Error::Unknown(format!(
                        "Cannot map shared memory {}",
                        String::from_utf8_lossy(map_str_bytes)
                    )));
                }

                Ok(Self {
                    id: ShMemId::from_slice(&map_str_bytes[0..20].try_into().unwrap()),
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
                    PSTR(&map_str_bytes as *const u8 as *mut u8),
                );
                if handle == HANDLE(0) {
                    return Err(Error::Unknown(format!(
                        "Cannot open shared memory {}",
                        String::from_utf8_lossy(&map_str_bytes)
                    )));
                }
                let map = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, map_size) as *mut u8;
                if map.is_null() {
                    return Err(Error::Unknown(format!(
                        "Cannot map shared memory {}",
                        String::from_utf8_lossy(&map_str_bytes)
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

    impl ShMem for Win32ShMem {
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
    impl Drop for Win32ShMem {
        fn drop(&mut self) {
            unsafe {
                UnmapViewOfFile(self.map as *mut c_void);
                CloseHandle(self.handle);
            }
        }
    }

    /// A ShMemProvider which uses win32 functions to provide shared memory mappings.
    #[derive(Clone, Debug)]
    pub struct Win32ShMemProvider {}

    impl Default for Win32ShMemProvider {
        fn default() -> Self {
            Self::new().unwrap()
        }
    }

    /// Implement ShMemProvider for Win32ShMemProvider
    impl ShMemProvider for Win32ShMemProvider {
        type Mem = Win32ShMem;

        fn new() -> Result<Self, Error> {
            Ok(Self {})
        }
        fn new_map(&mut self, map_size: usize) -> Result<Self::Mem, Error> {
            Win32ShMem::new_map(map_size)
        }

        fn from_id_and_size(&mut self, id: ShMemId, size: usize) -> Result<Self::Mem, Error> {
            Win32ShMem::from_id_and_size(id, size)
        }
    }
}

/// A cursor around [`ShMem`] that immitates [`std::io::Cursor`]. Notably, this implements [`Write`] for [`ShMem`] in std environments.
pub struct ShMemCursor<T: ShMem> {
    inner: T,
    pos: usize,
}

#[cfg(feature = "std")]
impl<T: ShMem> ShMemCursor<T> {
    pub fn from_shmem(shmem: T) -> Self {
        Self {
            inner: shmem,
            pos: 0,
        }
    }

    fn slice_mut(&mut self) -> &mut [u8] {
        &mut (self.inner.map_mut()[self.pos..])
    }
}

#[cfg(feature = "std")]
impl<T: ShMem> std::io::Write for ShMemCursor<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.slice_mut().write(buf) {
            Ok(w) => {
                self.pos += w;
                Ok(w)
            }
            Err(e) => Err(e),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
        match self.slice_mut().write_vectored(bufs) {
            Ok(w) => {
                self.pos += w;
                Ok(w)
            }
            Err(e) => Err(e),
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self.slice_mut().write_all(buf) {
            Ok(w) => {
                self.pos += buf.len();
                Ok(w)
            }
            Err(e) => Err(e),
        }
    }
}
