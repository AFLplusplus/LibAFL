//! A generic shared memory region to be used by any functions (queues or feedbacks
//! too.)

use alloc::{rc::Rc, string::ToString};
use core::{
    cell::RefCell,
    fmt::{self, Debug, Display},
    mem::ManuallyDrop,
};
#[cfg(feature = "std")]
use std::env;
#[cfg(all(unix, feature = "std"))]
use std::io::Read;
#[cfg(feature = "std")]
use std::io::Write;

use serde::{Deserialize, Serialize};
#[cfg(all(feature = "std", unix, not(target_os = "android")))]
pub use unix_shmem::{MmapShMem, MmapShMemProvider};
#[cfg(all(feature = "std", unix))]
pub use unix_shmem::{UnixShMem, UnixShMemProvider};
#[cfg(all(windows, feature = "std"))]
pub use win32_shmem::{Win32ShMem, Win32ShMemProvider};

#[cfg(all(unix, feature = "std"))]
use crate::bolts::os::pipes::Pipe;
#[cfg(all(feature = "std", unix))]
pub use crate::bolts::os::unix_shmem_server::{ServedShMemProvider, ShMemService};
use crate::{
    bolts::{AsMutSlice, AsSlice},
    Error,
};

/// The standard sharedmem provider
#[cfg(all(windows, feature = "std"))]
pub type StdShMemProvider = Win32ShMemProvider;
/// The standard sharedmem provider
#[cfg(all(target_os = "android", feature = "std"))]
pub type StdShMemProvider =
    RcShMemProvider<ServedShMemProvider<unix_shmem::ashmem::AshmemShMemProvider>>;
/// The standard sharedmem service
#[cfg(all(target_os = "android", feature = "std"))]
pub type StdShMemService = ShMemService<unix_shmem::ashmem::AshmemShMemProvider>;
/// The standard sharedmem provider
#[cfg(all(feature = "std", target_vendor = "apple"))]
pub type StdShMemProvider = RcShMemProvider<ServedShMemProvider<MmapShMemProvider>>;
#[cfg(all(feature = "std", target_vendor = "apple"))]
/// The standard sharedmem service
pub type StdShMemService = ShMemService<MmapShMemProvider>;
/// The default [`ShMemProvider`] for this os.
#[cfg(all(
    feature = "std",
    unix,
    not(any(target_os = "android", target_vendor = "apple"))
))]
pub type StdShMemProvider = UnixShMemProvider;
/// The standard sharedmem service
#[cfg(any(
    not(any(target_os = "android", target_vendor = "apple")),
    not(feature = "std")
))]
pub type StdShMemService = DummyShMemService;

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
    /// Create a new id from a fixed-size string/bytes array
    /// It should contain a valid cstring.
    #[must_use]
    pub fn from_array(array: &[u8; 20]) -> Self {
        Self { id: *array }
    }

    /// Try to create a new id from a bytes string.
    /// The slice must have a length of at least 20 bytes and contain a valid cstring.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_array(&slice[0..20].try_into()?))
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
    pub fn as_array(&self) -> &[u8; 20] {
        &self.id
    }

    /// Returns the first null-byte in or the end of the buffer
    #[must_use]
    pub fn null_pos(&self) -> usize {
        self.id.iter().position(|&c| c == 0).unwrap()
    }

    /// Returns a `str` representation of this [`ShMemId`]
    #[must_use]
    pub fn as_str(&self) -> &str {
        alloc::str::from_utf8(&self.id[..self.null_pos()]).unwrap()
    }
}
impl AsSlice for ShMemId {
    type Entry = u8;
    fn as_slice(&self) -> &[u8] {
        &self.id
    }
}

impl From<ShMemId> for i32 {
    fn from(id: ShMemId) -> i32 {
        id.as_str().parse().unwrap()
    }
}

impl Display for ShMemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A [`ShMem`] is an interface to shared maps.
/// They are the backbone of [`crate::bolts::llmp`] for inter-process communication.
/// All you need for scaling on a new target is to implement this interface, as well as the respective [`ShMemProvider`].
pub trait ShMem: Sized + Debug + Clone + AsSlice<Entry = u8> + AsMutSlice<Entry = u8> {
    /// Get the id of this shared memory mapping
    fn id(&self) -> ShMemId;

    /// Get the size of this mapping
    fn len(&self) -> usize;

    /// Check if the mapping is empty
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Convert to an owned object reference
    ///
    /// # Safety
    /// This function is not safe as the object may be not initialized.
    /// The user is responsible to initialize the object with something like
    /// `*shmem.as_object_mut::<T>() = T::new();`
    unsafe fn as_object<T: Sized + 'static>(&self) -> &T {
        assert!(self.len() >= core::mem::size_of::<T>());
        (self.as_slice().as_ptr() as *const () as *const T)
            .as_ref()
            .unwrap()
    }

    /// Convert to an owned object mutable reference
    ///
    /// # Safety
    /// This function is not safe as the object may be not initialized.
    /// The user is responsible to initialize the object with something like
    /// `*shmem.as_object_mut::<T>() = T::new();`
    unsafe fn as_object_mut<T: Sized + 'static>(&mut self) -> &mut T {
        assert!(self.len() >= core::mem::size_of::<T>());
        (self.as_mut_slice().as_mut_ptr() as *mut () as *mut T)
            .as_mut()
            .unwrap()
    }

    /// Get the description of the shared memory mapping
    fn description(&self) -> ShMemDescription {
        ShMemDescription {
            size: self.len(),
            id: self.id(),
        }
    }

    /// Write this map's config to env
    #[cfg(feature = "std")]
    fn write_to_env(&self, env_name: &str) -> Result<(), Error> {
        let map_size = self.len();
        let map_size_env = format!("{env_name}_SIZE");
        env::set_var(env_name, self.id().to_string());
        env::set_var(map_size_env, format!("{map_size}"));
        Ok(())
    }
}

/// A [`ShMemProvider`] provides access to shared maps.
/// They are the backbone of [`crate::bolts::llmp`] for inter-process communication.
/// All you need for scaling on a new target is to implement this interface, as well as the respective [`ShMem`].
pub trait ShMemProvider: Clone + Default + Debug {
    /// The actual shared map handed out by this [`ShMemProvider`].
    type ShMem: ShMem;

    /// Create a new instance of the provider
    fn new() -> Result<Self, Error>;

    /// Create a new shared memory mapping
    fn new_shmem(&mut self, map_size: usize) -> Result<Self::ShMem, Error>;

    /// Get a mapping given its id and size
    fn shmem_from_id_and_size(&mut self, id: ShMemId, size: usize) -> Result<Self::ShMem, Error>;

    /// Create a new shared memory mapping to hold an object of the given type
    fn new_shmem_object<T: Sized + 'static>(&mut self) -> Result<Self::ShMem, Error> {
        self.new_shmem(core::mem::size_of::<T>())
    }

    /// Get a mapping given its id to hold an object of the given type
    fn shmem_object_from_id<T: Sized + 'static>(
        &mut self,
        id: ShMemId,
    ) -> Result<Self::ShMem, Error> {
        self.shmem_from_id_and_size(id, core::mem::size_of::<T>())
    }

    /// Get a mapping given a description
    fn shmem_from_description(
        &mut self,
        description: ShMemDescription,
    ) -> Result<Self::ShMem, Error> {
        self.shmem_from_id_and_size(description.id, description.size)
    }

    /// Create a new sharedmap reference from an existing `id` and `len`
    fn clone_ref(&mut self, mapping: &Self::ShMem) -> Result<Self::ShMem, Error> {
        self.shmem_from_id_and_size(mapping.id(), mapping.len())
    }

    /// Reads an existing map config from env vars, then maps it
    #[cfg(feature = "std")]
    fn existing_from_env(&mut self, env_name: &str) -> Result<Self::ShMem, Error> {
        let map_shm_str = env::var(env_name)?;
        let map_size = str::parse::<usize>(&env::var(format!("{env_name}_SIZE"))?)?;
        self.shmem_from_description(ShMemDescription::from_string_and_size(
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
    fn release_shmem(&mut self, _shmem: &mut Self::ShMem) {
        // do nothing
    }
}

/// A Reference Counted shared map,
/// that can use internal mutability.
/// Useful if the `ShMemProvider` needs to keep local state.
#[derive(Debug, Clone)]
pub struct RcShMem<T: ShMemProvider> {
    internal: ManuallyDrop<T::ShMem>,
    provider: Rc<RefCell<T>>,
}

impl<T> ShMem for RcShMem<T>
where
    T: ShMemProvider + Debug,
{
    fn id(&self) -> ShMemId {
        self.internal.id()
    }

    fn len(&self) -> usize {
        self.internal.len()
    }
}

impl<T> AsSlice for RcShMem<T>
where
    T: ShMemProvider + Debug,
{
    type Entry = u8;
    fn as_slice(&self) -> &[u8] {
        self.internal.as_slice()
    }
}

impl<T> AsMutSlice for RcShMem<T>
where
    T: ShMemProvider + Debug,
{
    type Entry = u8;
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.internal.as_mut_slice()
    }
}

impl<T: ShMemProvider> Drop for RcShMem<T> {
    fn drop(&mut self) {
        self.provider.borrow_mut().release_shmem(&mut self.internal);
    }
}

/// A Reference Counted `ShMemProvider`,
/// that can use internal mutability.
/// Useful if the `ShMemProvider` needs to keep local state.
#[derive(Debug, Clone)]
#[cfg(all(unix, feature = "std"))]
pub struct RcShMemProvider<SP>
where
    SP: ShMemProvider,
{
    /// The wrapped [`ShMemProvider`].
    internal: Rc<RefCell<SP>>,
    /// A pipe the child uses to communicate progress to the parent after fork.
    /// This prevents a potential race condition when using the [`ShMemService`].
    #[cfg(unix)]
    child_parent_pipe: Option<Pipe>,
    #[cfg(unix)]
    /// A pipe the parent uses to communicate progress to the child after fork.
    /// This prevents a potential race condition when using the [`ShMemService`].
    parent_child_pipe: Option<Pipe>,
}

//#[cfg(all(unix, feature = "std"))]
//unsafe impl<SP: ShMemProvider> Send for RcShMemProvider<SP> {}

#[cfg(all(unix, feature = "std"))]
impl<SP> ShMemProvider for RcShMemProvider<SP>
where
    SP: ShMemProvider + Debug,
{
    type ShMem = RcShMem<SP>;

    fn new() -> Result<Self, Error> {
        Ok(Self {
            internal: Rc::new(RefCell::new(SP::new()?)),
            child_parent_pipe: None,
            parent_child_pipe: None,
        })
    }

    fn new_shmem(&mut self, map_size: usize) -> Result<Self::ShMem, Error> {
        Ok(Self::ShMem {
            internal: ManuallyDrop::new(self.internal.borrow_mut().new_shmem(map_size)?),
            provider: self.internal.clone(),
        })
    }

    fn shmem_from_id_and_size(&mut self, id: ShMemId, size: usize) -> Result<Self::ShMem, Error> {
        Ok(Self::ShMem {
            internal: ManuallyDrop::new(
                self.internal
                    .borrow_mut()
                    .shmem_from_id_and_size(id, size)?,
            ),
            provider: self.internal.clone(),
        })
    }

    fn release_shmem(&mut self, map: &mut Self::ShMem) {
        self.internal.borrow_mut().release_shmem(&mut map.internal);
    }

    fn clone_ref(&mut self, mapping: &Self::ShMem) -> Result<Self::ShMem, Error> {
        Ok(Self::ShMem {
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
            //let child_shmem = self.internal.borrow_mut().clone();
            //self.internal = Rc::new(RefCell::new(child_shmem));
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
impl<SP> RcShMemProvider<SP>
where
    SP: ShMemProvider,
{
    /// "set" the "latch"
    /// (we abuse `pipes` as `semaphores`, as they don't need an additional shared mem region.)
    fn pipe_set(pipe: &mut Option<Pipe>) -> Result<(), Error> {
        match pipe {
            Some(pipe) => {
                let ok = [0_u8; 4];
                pipe.write_all(&ok)?;
                Ok(())
            }
            None => Err(Error::illegal_state(
                "Unexpected `None` Pipe in RcShMemProvider! Missing post_fork()?".to_string(),
            )),
        }
    }

    /// "await" the "latch"
    fn pipe_await(pipe: &mut Option<Pipe>) -> Result<(), Error> {
        match pipe {
            Some(pipe) => {
                let ok = [0_u8; 4];
                let mut ret = ok;
                pipe.read_exact(&mut ret)?;
                if ret == ok {
                    Ok(())
                } else {
                    Err(Error::unknown(format!(
                        "Wrong result read from pipe! Expected 0, got {:?}",
                        ret
                    )))
                }
            }
            None => Err(Error::illegal_state(
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
impl<SP> Default for RcShMemProvider<SP>
where
    SP: ShMemProvider + Debug,
{
    fn default() -> Self {
        Self::new().unwrap()
    }
}

/// A Unix sharedmem implementation.
///
/// On Android, this is partially reused to wrap [`unix_shmem::ashmem::AshmemShMem`],
/// Although for an [`ServedShMemProvider`] using a unix domain socket
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
    pub type UnixShMem = default::CommonUnixShMem;

    /// Mmap [`ShMem`] for Unix
    #[cfg(not(target_os = "android"))]
    pub use default::MmapShMem;
    /// Mmap [`ShMemProvider`] for Unix
    #[cfg(not(target_os = "android"))]
    pub use default::MmapShMemProvider;

    #[cfg(all(unix, feature = "std", not(target_os = "android")))]
    mod default {

        use alloc::string::ToString;
        use core::{ptr, slice};
        use std::{io::Write, process};

        use libc::{
            c_int, c_long, c_uchar, c_uint, c_ulong, c_ushort, close, ftruncate, mmap, munmap,
            perror, shm_open, shm_unlink, shmat, shmctl, shmget,
        };

        use crate::{
            bolts::{
                shmem::{ShMem, ShMemId, ShMemProvider},
                AsMutSlice, AsSlice,
            },
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

        const MAX_MMAP_FILENAME_LEN: usize = 256;

        /// Mmap-based The sharedmap impl for unix using [`shm_open`] and [`mmap`].
        /// Default on `MacOS` and `iOS`, where we need a central point to unmap
        /// shared mem segments for dubious Mach kernel reasons.
        #[derive(Clone, Debug)]
        pub struct MmapShMem {
            /// The path of this shared memory segment.
            /// None in case we didn't [`shm_open`] this ourselves, but someone sent us the FD.
            filename_path: Option<[u8; MAX_MMAP_FILENAME_LEN]>,
            /// The size of this map
            map_size: usize,
            /// The map ptr
            map: *mut u8,
            /// The shmem id, containing the file descriptor and size, to send over the wire
            id: ShMemId,
            /// The file descriptor of the shmem
            shm_fd: c_int,
        }

        impl MmapShMem {
            /// Create a new [`MmapShMem`]
            pub fn new(map_size: usize, shmem_ctr: usize) -> Result<Self, Error> {
                unsafe {
                    let mut filename_path = [0_u8; MAX_MMAP_FILENAME_LEN];
                    write!(
                        &mut filename_path[..MAX_MMAP_FILENAME_LEN - 1],
                        "/libafl_{}_{}",
                        process::id(),
                        shmem_ctr
                    )?;

                    /* create the shared memory segment as if it was a file */
                    let shm_fd = shm_open(
                        filename_path.as_ptr() as *const _,
                        libc::O_CREAT | libc::O_RDWR | libc::O_EXCL,
                        0o600,
                    );
                    if shm_fd == -1 {
                        perror(b"shm_open\0".as_ptr() as *const _);
                        return Err(Error::unknown(format!(
                            "Failed to shm_open map with id {:?}",
                            shmem_ctr
                        )));
                    }

                    /* configure the size of the shared memory segment */
                    if ftruncate(shm_fd, map_size.try_into()?) != 0 {
                        perror(b"ftruncate\0".as_ptr() as *const _);
                        shm_unlink(filename_path.as_ptr() as *const _);
                        return Err(Error::unknown(format!(
                            "setup_shm(): ftruncate() failed for map with id {:?}",
                            shmem_ctr
                        )));
                    }

                    /* map the shared memory segment to the address space of the process */
                    let map = mmap(
                        ptr::null_mut(),
                        map_size,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED,
                        shm_fd,
                        0,
                    );
                    if map == libc::MAP_FAILED || map.is_null() {
                        perror(b"mmap\0".as_ptr() as *const _);
                        close(shm_fd);
                        shm_unlink(filename_path.as_ptr() as *const _);
                        return Err(Error::unknown(format!(
                            "mmap() failed for map with id {:?}",
                            shmem_ctr
                        )));
                    }

                    Ok(Self {
                        filename_path: Some(filename_path),
                        map: map as *mut u8,
                        map_size,
                        shm_fd,
                        id: ShMemId::from_string(&format!("{shm_fd}")),
                    })
                }
            }

            fn shmem_from_id_and_size(id: ShMemId, map_size: usize) -> Result<Self, Error> {
                unsafe {
                    let shm_fd: i32 = id.to_string().parse().unwrap();

                    /* map the shared memory segment to the address space of the process */
                    let map = mmap(
                        ptr::null_mut(),
                        map_size,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED,
                        shm_fd,
                        0,
                    );
                    if map == libc::MAP_FAILED || map.is_null() {
                        perror(b"mmap\0".as_ptr() as *const _);
                        close(shm_fd);
                        return Err(Error::unknown(format!(
                            "mmap() failed for map with fd {:?}",
                            shm_fd
                        )));
                    }

                    Ok(Self {
                        filename_path: None,
                        map: map as *mut u8,
                        map_size,
                        shm_fd,
                        id: ShMemId::from_string(&format!("{shm_fd}")),
                    })
                }
            }
        }

        /// A [`ShMemProvider`] which uses `shmget`/`shmat`/`shmctl` to provide shared memory mappings.
        #[cfg(unix)]
        #[derive(Clone, Debug)]
        pub struct MmapShMemProvider {
            current_shmem_id: usize,
        }

        unsafe impl Send for MmapShMemProvider {}

        #[cfg(unix)]
        impl Default for MmapShMemProvider {
            fn default() -> Self {
                Self::new().unwrap()
            }
        }

        /// Implement [`ShMemProvider`] for [`MmapShMemProvider`].
        #[cfg(unix)]
        impl ShMemProvider for MmapShMemProvider {
            type ShMem = MmapShMem;

            fn new() -> Result<Self, Error> {
                Ok(Self {
                    current_shmem_id: 0,
                })
            }
            fn new_shmem(&mut self, map_size: usize) -> Result<Self::ShMem, Error> {
                self.current_shmem_id += 1;
                MmapShMem::new(map_size, self.current_shmem_id)
            }

            fn shmem_from_id_and_size(
                &mut self,
                id: ShMemId,
                size: usize,
            ) -> Result<Self::ShMem, Error> {
                MmapShMem::shmem_from_id_and_size(id, size)
            }
        }

        impl ShMem for MmapShMem {
            fn id(&self) -> ShMemId {
                self.id
            }

            fn len(&self) -> usize {
                self.map_size
            }
        }

        impl AsSlice for MmapShMem {
            type Entry = u8;
            fn as_slice(&self) -> &[u8] {
                unsafe { slice::from_raw_parts(self.map, self.map_size) }
            }
        }

        impl AsMutSlice for MmapShMem {
            type Entry = u8;
            fn as_mut_slice(&mut self) -> &mut [u8] {
                unsafe { slice::from_raw_parts_mut(self.map, self.map_size) }
            }
        }

        impl Drop for MmapShMem {
            fn drop(&mut self) {
                unsafe {
                    assert!(
                        !self.map.is_null(),
                        "Map should never be null for MmapShMem (on Drop)"
                    );

                    munmap(self.map as *mut _, self.map_size);
                    self.map = ptr::null_mut();

                    assert!(
                        self.shm_fd != -1,
                        "FD should never be -1 for MmapShMem (on Drop)"
                    );

                    // None in case we didn't [`shm_open`] this ourselves, but someone sent us the FD.
                    if let Some(filename_path) = self.filename_path {
                        shm_unlink(filename_path.as_ptr() as *const _);
                    }
                }
            }
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
            #[allow(unused_qualifications)]
            pub fn new(map_size: usize) -> Result<Self, Error> {
                #[cfg(any(target_os = "solaris", target_os = "illumos"))]
                const SHM_R: libc::c_int = 0o400;
                #[cfg(not(any(target_os = "solaris", target_os = "illumos")))]
                const SHM_R: libc::c_int = libc::SHM_R;
                #[cfg(any(target_os = "solaris", target_os = "illumos"))]
                const SHM_W: libc::c_int = 0o200;
                #[cfg(not(any(target_os = "solaris", target_os = "illumos")))]
                const SHM_W: libc::c_int = libc::SHM_W;

                unsafe {
                    let os_id = shmget(
                        libc::IPC_PRIVATE,
                        map_size,
                        libc::IPC_CREAT | libc::IPC_EXCL | SHM_R | SHM_W,
                    );

                    if os_id < 0_i32 {
                        return Err(Error::unknown(format!("Failed to allocate a shared mapping of size {map_size} - check OS limits (i.e shmall, shmmax)")));
                    }

                    let map = shmat(os_id, ptr::null(), 0) as *mut c_uchar;

                    if map as c_int == -1 || map.is_null() {
                        shmctl(os_id, libc::IPC_RMID, ptr::null_mut());
                        return Err(Error::unknown(
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
            pub fn shmem_from_id_and_size(id: ShMemId, map_size: usize) -> Result<Self, Error> {
                unsafe {
                    let id_int: i32 = id.into();
                    let map = shmat(id_int, ptr::null(), 0) as *mut c_uchar;

                    if map.is_null() || map == ptr::null_mut::<c_uchar>().wrapping_sub(1) {
                        return Err(Error::unknown(
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
        }

        impl AsSlice for CommonUnixShMem {
            type Entry = u8;
            fn as_slice(&self) -> &[u8] {
                unsafe { slice::from_raw_parts(self.map, self.map_size) }
            }
        }

        impl AsMutSlice for CommonUnixShMem {
            type Entry = u8;
            fn as_mut_slice(&mut self) -> &mut [u8] {
                unsafe { slice::from_raw_parts_mut(self.map, self.map_size) }
            }
        }

        /// [`Drop`] implementation for [`UnixShMem`], which cleans up the mapping.
        #[cfg(unix)]
        impl Drop for CommonUnixShMem {
            fn drop(&mut self) {
                unsafe {
                    let id_int: i32 = self.id.into();
                    shmctl(id_int, libc::IPC_RMID, ptr::null_mut());
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
            type ShMem = CommonUnixShMem;

            fn new() -> Result<Self, Error> {
                Ok(Self {})
            }
            fn new_shmem(&mut self, map_size: usize) -> Result<Self::ShMem, Error> {
                CommonUnixShMem::new(map_size)
            }

            fn shmem_from_id_and_size(
                &mut self,
                id: ShMemId,
                size: usize,
            ) -> Result<Self::ShMem, Error> {
                CommonUnixShMem::shmem_from_id_and_size(id, size)
            }
        }
    }

    /// Module containing `ashmem` shared memory support, commonly used on Android.
    #[cfg(all(unix, feature = "std"))]
    pub mod ashmem {
        use alloc::string::ToString;
        use core::{ptr, slice};
        use std::ffi::CString;

        use libc::{
            c_uint, c_ulong, c_void, close, ioctl, mmap, open, MAP_SHARED, O_RDWR, PROT_READ,
            PROT_WRITE,
        };

        use crate::{
            bolts::{
                shmem::{ShMem, ShMemId, ShMemProvider},
                AsMutSlice, AsSlice,
            },
            Error,
        };

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

        const ASHMEM_GET_SIZE: c_ulong = 0x00007704;
        const ASHMEM_UNPIN: c_ulong = 0x40087708;
        //const ASHMEM_SET_NAME: c_long = 0x41007701;
        const ASHMEM_SET_SIZE: c_ulong = 0x40087703;

        impl AshmemShMem {
            /// Create a new shared memory mapping, using shmget/shmat
            pub fn new(map_size: usize) -> Result<Self, Error> {
                unsafe {
                    let device_path = CString::new(
                        if let Ok(boot_id) =
                            std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                        {
                            let path_str = format!("/dev/ashmem{boot_id}").trim().to_string();
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
                        return Err(Error::unknown(format!(
                            "Failed to open the ashmem device at {:?}",
                            device_path
                        )));
                    }

                    //if ioctl(fd, ASHMEM_SET_NAME, name) != 0 {
                    //close(fd);
                    //return Err(Error::unknown("Failed to set the ashmem mapping's name".to_string()));
                    //};

                    #[allow(trivial_numeric_casts)]
                    if ioctl(fd, ASHMEM_SET_SIZE as _, map_size) != 0 {
                        close(fd);
                        return Err(Error::unknown(
                            "Failed to set the ashmem mapping's size".to_string(),
                        ));
                    };

                    let map = mmap(
                        ptr::null_mut(),
                        map_size,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED,
                        fd,
                        0,
                    );
                    if map == usize::MAX as *mut c_void {
                        close(fd);
                        return Err(Error::unknown(
                            "Failed to map the ashmem mapping".to_string(),
                        ));
                    }

                    Ok(Self {
                        id: ShMemId::from_string(&format!("{fd}")),
                        map: map as *mut u8,
                        map_size,
                    })
                }
            }

            /// Get a [`crate::bolts::shmem::unix_shmem::UnixShMem`] of the existing [`ShMem`] mapping identified by id.
            pub fn shmem_from_id_and_size(id: ShMemId, map_size: usize) -> Result<Self, Error> {
                unsafe {
                    let fd: i32 = id.to_string().parse().unwrap();
                    #[allow(trivial_numeric_casts, clippy::cast_sign_loss)]
                    if ioctl(fd, ASHMEM_GET_SIZE as _) as u32 as usize != map_size {
                        return Err(Error::unknown(
                            "The mapping's size differs from the requested size".to_string(),
                        ));
                    };

                    let map = mmap(
                        ptr::null_mut(),
                        map_size,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED,
                        fd,
                        0,
                    );
                    if map == usize::MAX as *mut c_void {
                        close(fd);
                        return Err(Error::unknown(
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
        }

        impl AsSlice for AshmemShMem {
            type Entry = u8;
            fn as_slice(&self) -> &[u8] {
                unsafe { slice::from_raw_parts(self.map, self.map_size) }
            }
        }

        impl AsMutSlice for AshmemShMem {
            type Entry = u8;

            fn as_mut_slice(&mut self) -> &mut [u8] {
                unsafe { slice::from_raw_parts_mut(self.map, self.map_size) }
            }
        }

        /// [`Drop`] implementation for [`AshmemShMem`], which cleans up the mapping.
        #[cfg(unix)]
        impl Drop for AshmemShMem {
            #[allow(trivial_numeric_casts)]
            fn drop(&mut self) {
                unsafe {
                    let fd: i32 = self.id.to_string().parse().unwrap();

                    #[allow(trivial_numeric_casts)]
                    #[allow(clippy::cast_sign_loss)]
                    let length = ioctl(fd, ASHMEM_GET_SIZE as _) as u32;

                    let ap = ashmem_pin {
                        offset: 0,
                        len: length,
                    };

                    ioctl(fd, ASHMEM_UNPIN as _, &ap);
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
            type ShMem = AshmemShMem;

            fn new() -> Result<Self, Error> {
                Ok(Self {})
            }

            fn new_shmem(&mut self, map_size: usize) -> Result<Self::ShMem, Error> {
                let mapping = AshmemShMem::new(map_size)?;
                Ok(mapping)
            }

            fn shmem_from_id_and_size(
                &mut self,
                id: ShMemId,
                size: usize,
            ) -> Result<Self::ShMem, Error> {
                AshmemShMem::shmem_from_id_and_size(id, size)
            }
        }
    }
}

/// Then `win32` implementation for shared memory.
#[cfg(all(feature = "std", windows))]
pub mod win32_shmem {

    use alloc::string::String;
    use core::{
        ffi::c_void,
        fmt::{self, Debug, Formatter},
        slice,
    };

    use uuid::Uuid;

    use crate::{
        bolts::{
            shmem::{ShMem, ShMemId, ShMemProvider},
            AsMutSlice, AsSlice,
        },
        Error,
    };

    const INVALID_HANDLE_VALUE: isize = -1;

    use windows::{
        core::PCSTR,
        Win32::{
            Foundation::{CloseHandle, BOOL, HANDLE},
            System::Memory::{
                CreateFileMappingA, MapViewOfFile, OpenFileMappingA, UnmapViewOfFile,
                FILE_MAP_ALL_ACCESS, PAGE_READWRITE,
            },
        },
    };

    /// The default Sharedmap impl for windows using shmctl & shmget
    #[derive(Clone)]
    pub struct Win32ShMem {
        id: ShMemId,
        handle: HANDLE,
        map: *mut u8,
        map_size: usize,
    }

    impl Debug for Win32ShMem {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.debug_struct("Win32ShMem")
                .field("id", &self.id)
                .field("handle", &self.handle.0)
                .field("map", &self.map)
                .field("map_size", &self.map_size)
                .finish()
        }
    }

    impl Win32ShMem {
        fn new_shmem(map_size: usize) -> Result<Self, Error> {
            unsafe {
                let uuid = Uuid::new_v4();
                let mut map_str = format!("libafl_{}", uuid.simple());
                let map_str_bytes = map_str.as_mut_vec();
                map_str_bytes[19] = 0; // Trucate to size 20
                let handle = CreateFileMappingA(
                    HANDLE(INVALID_HANDLE_VALUE),
                    None,
                    PAGE_READWRITE,
                    0,
                    map_size as u32,
                    PCSTR(map_str_bytes.as_mut_ptr()),
                )?;

                let map = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, map_size) as *mut u8;
                if map.is_null() {
                    return Err(Error::unknown(format!(
                        "Cannot map shared memory {}",
                        String::from_utf8_lossy(map_str_bytes)
                    )));
                }

                Ok(Self {
                    id: ShMemId::try_from_slice(map_str_bytes).unwrap(),
                    handle,
                    map,
                    map_size,
                })
            }
        }

        fn shmem_from_id_and_size(id: ShMemId, map_size: usize) -> Result<Self, Error> {
            unsafe {
                let map_str_bytes = id.id;
                // Unlike MapViewOfFile this one needs u32
                let handle = OpenFileMappingA(
                    FILE_MAP_ALL_ACCESS.0,
                    BOOL(0),
                    PCSTR(map_str_bytes.as_ptr() as *mut _),
                )?;

                let map = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, map_size) as *mut u8;
                if map.is_null() {
                    return Err(Error::unknown(format!(
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
    }

    impl AsSlice for Win32ShMem {
        type Entry = u8;
        fn as_slice(&self) -> &[u8] {
            unsafe { slice::from_raw_parts(self.map, self.map_size) }
        }
    }
    impl AsMutSlice for Win32ShMem {
        type Entry = u8;
        fn as_mut_slice(&mut self) -> &mut [u8] {
            unsafe { slice::from_raw_parts_mut(self.map, self.map_size) }
        }
    }

    /// Deinit sharedmaps on [`Drop`]
    impl Drop for Win32ShMem {
        fn drop(&mut self) {
            unsafe {
                UnmapViewOfFile(self.map as *mut c_void);
                CloseHandle(self.handle);
            }
        }
    }

    /// A [`ShMemProvider`] which uses `win32` functions to provide shared memory mappings.
    #[derive(Clone, Debug)]
    pub struct Win32ShMemProvider {}

    impl Default for Win32ShMemProvider {
        fn default() -> Self {
            Self::new().unwrap()
        }
    }

    /// Implement [`ShMemProvider`] for [`Win32ShMemProvider`]
    impl ShMemProvider for Win32ShMemProvider {
        type ShMem = Win32ShMem;

        fn new() -> Result<Self, Error> {
            Ok(Self {})
        }
        fn new_shmem(&mut self, map_size: usize) -> Result<Self::ShMem, Error> {
            Win32ShMem::new_shmem(map_size)
        }

        fn shmem_from_id_and_size(
            &mut self,
            id: ShMemId,
            size: usize,
        ) -> Result<Self::ShMem, Error> {
            Win32ShMem::shmem_from_id_and_size(id, size)
        }
    }
}

/// A `ShMemService` dummy, that does nothing on start.
/// Drop in for targets that don't need a server for ref counting and page creation.
#[derive(Debug)]
pub struct DummyShMemService;

impl DummyShMemService {
    /// Create a new [`DummyShMemService`] that does nothing.
    /// Useful only to have the same API for [`StdShMemService`] on Operating Systems that don't need it.
    #[inline]
    pub fn start() -> Result<Self, Error> {
        Ok(Self {})
    }
}

/// A cursor around [`ShMem`] that immitates [`std::io::Cursor`]. Notably, this implements [`Write`] for [`ShMem`] in std environments.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct ShMemCursor<T: ShMem> {
    inner: T,
    pos: usize,
}

#[cfg(feature = "std")]
impl<T: ShMem> ShMemCursor<T> {
    /// Create a new [`ShMemCursor`] around [`ShMem`]
    pub fn new(shmem: T) -> Self {
        Self {
            inner: shmem,
            pos: 0,
        }
    }

    /// Slice from the current location on this map to the end, mutable
    fn empty_slice_mut(&mut self) -> &mut [u8] {
        &mut (self.inner.as_mut_slice()[self.pos..])
    }
}

#[cfg(feature = "std")]
impl<T: ShMem> Write for ShMemCursor<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.empty_slice_mut().write(buf) {
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
        match self.empty_slice_mut().write_vectored(bufs) {
            Ok(w) => {
                self.pos += w;
                Ok(w)
            }
            Err(e) => Err(e),
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self.empty_slice_mut().write_all(buf) {
            Ok(w) => {
                self.pos += buf.len();
                Ok(w)
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(feature = "std")]
impl<T: ShMem> std::io::Seek for ShMemCursor<T> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        let effective_new_pos = match pos {
            std::io::SeekFrom::Start(s) => s,
            std::io::SeekFrom::End(offset) => {
                let map_len = self.inner.as_slice().len();
                i64::try_from(map_len).unwrap();
                let signed_pos = map_len as i64;
                let effective = signed_pos.checked_add(offset).unwrap();
                assert!(effective >= 0);
                effective.try_into().unwrap()
            }
            std::io::SeekFrom::Current(offset) => {
                let current_pos = self.pos;
                i64::try_from(current_pos).unwrap();
                let signed_pos = current_pos as i64;
                let effective = signed_pos.checked_add(offset).unwrap();
                assert!(effective >= 0);
                effective.try_into().unwrap()
            }
        };
        usize::try_from(effective_new_pos).unwrap();
        self.pos = effective_new_pos as usize;
        Ok(effective_new_pos)
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use serial_test::serial;

    use crate::bolts::{
        shmem::{ShMemProvider, StdShMemProvider},
        AsMutSlice, AsSlice,
    };

    #[test]
    #[serial]
    fn test_shmem_service() {
        let mut provider = StdShMemProvider::new().unwrap();
        let mut map = provider.new_shmem(1024).unwrap();
        map.as_mut_slice()[0] = 1;
        assert!(map.as_slice()[0] == 1);
    }
}
