//! Stores and restores state when a client needs to relaunch.
//! Uses a [`ShMem`] up to a threshold, then write to disk.
use alloc::string::{String, ToString};
use core::{
    hash::{BuildHasher, Hasher},
    marker::PhantomData,
    mem::size_of,
    ptr, slice,
    sync::atomic::{Ordering, fence},
};
use std::{
    env::temp_dir,
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
};

use ahash::RandomState;
use libafl_core::Error;
use serde::{Serialize, de::DeserializeOwned};

use crate::shmem::{ShMem, ShMemProvider};

/// If the saved page content equals exactly this buf, the restarted child wants to exit cleanly.
const EXITING_MAGIC: &[u8; 16] = b"LIBAFL_EXIT_NOW\0";

/// The header stored at the start of the shared map, followed immediately at
/// `size_of::<StateShMemContent>()` by either serialized state bytes or a tmpfile name.
#[repr(C)]
struct StateShMemContent {
    /// Stored as `u8` (not `bool`) and read/written via volatile + fences so corrupt peer bytes
    /// are sound and `&self` reads through `ShMem::deref` avoid Stacked Borrows `UnsafeCell` retags.
    is_disk: u8,
    buf_len: usize,
}

const _: () = assert!(align_of::<StateShMemContent>() <= 8);

impl<SHM, SP> StateRestorer<SHM, SP>
where
    SHM: ShMem,
    SP: ShMemProvider<ShMem = SHM>,
{
    #[inline]
    fn header_ptr(&self) -> *const StateShMemContent {
        #[expect(clippy::cast_ptr_alignment)]
        let ptr = self.shmem.as_ptr().cast::<StateShMemContent>();
        debug_assert!(ptr.is_aligned());
        ptr
    }

    #[inline]
    fn header_mut_ptr(&mut self) -> *mut StateShMemContent {
        #[expect(clippy::cast_ptr_alignment)]
        let ptr = self.shmem.as_mut_ptr().cast::<StateShMemContent>();
        debug_assert!(ptr.is_aligned());
        ptr
    }

    #[inline]
    fn is_disk_unordered(&self) -> bool {
        if self.shmem.len() < size_of::<StateShMemContent>() {
            return false;
        }
        let hdr = self.header_ptr();
        unsafe { ptr::read_volatile(&raw const (*hdr).is_disk) != 0 }
    }

    #[cfg(test)]
    fn is_disk(&self) -> bool {
        let disk = self.is_disk_unordered();
        if self.shmem.len() >= size_of::<StateShMemContent>() {
            fence(Ordering::Acquire);
        }
        disk
    }

    /// Get a payload length that is safe to read from this map, or an error if out of bounds.
    fn buf_len_checked(&self) -> Result<usize, Error> {
        let shmem_size = self.mapsize();
        if shmem_size < size_of::<StateShMemContent>() {
            return Err(Error::illegal_state("ShMem too small"));
        }
        let hdr = self.header_ptr();
        let buf_len = unsafe { ptr::read_volatile(&raw const (*hdr).buf_len) };
        fence(Ordering::Acquire);
        if size_of::<StateShMemContent>().saturating_add(buf_len) > shmem_size {
            Err(Error::illegal_state(format!(
                "Stored buf_len is larger than the shared map! Shared data corrupted? Expected {shmem_size} bytes max, but got {} (buf_len {buf_len})",
                size_of::<StateShMemContent>().saturating_add(buf_len)
            )))
        } else {
            Ok(buf_len)
        }
    }

    /// Gets the (tmp-)filename, if the contents are stored on disk.
    fn tmpfile(&self) -> Result<Option<PathBuf>, Error> {
        let len = self.buf_len_checked()?;
        if len == 0 || !self.is_disk_unordered() {
            return Ok(None);
        }
        let bytes = unsafe {
            slice::from_raw_parts(self.shmem.as_ptr().add(size_of::<StateShMemContent>()), len)
        };
        Ok(Some(
            temp_dir().join(postcard::from_bytes::<String>(bytes)?),
        ))
    }
}

/// A [`StateRestorer`] saves and restores bytes to a shared map.
///
/// If the state gets larger than the preallocated [`ShMem`] shared map,
/// it will instead write to disk, and store the file name into the map.
/// Writing to [`StateRestorer`] multiple times is not allowed.
#[derive(Debug, Clone)]
pub struct StateRestorer<SHM, SP> {
    shmem: SHM,
    phantom: PhantomData<*const SP>,
}

impl<SHM, SP> StateRestorer<SHM, SP>
where
    SHM: ShMem,
    SP: ShMemProvider<ShMem = SHM>,
{
    /// Get the map size backing this [`StateRestorer`].
    pub fn mapsize(&self) -> usize {
        self.shmem.len()
    }

    /// Writes this [`StateRestorer`] to env variable, to be restored later
    ///
    /// # Safety
    /// Alters the env. Should only be called from a single thread.
    pub unsafe fn write_to_env(&self, env_name: &str) -> Result<(), Error> {
        unsafe { self.shmem.write_to_env(env_name) }
    }

    /// Create a [`StateRestorer`] from `env` variable name
    pub fn from_env(shmem_provider: &mut SP, env_name: &str) -> Result<Self, Error> {
        Ok(Self {
            shmem: shmem_provider.existing_from_env(env_name)?,
            phantom: PhantomData,
        })
    }

    /// Create a new [`StateRestorer`].
    pub fn new(shmem: SHM) -> Self {
        let mut ret = Self {
            shmem,
            phantom: PhantomData,
        };
        ret.reset();
        ret
    }

    /// Saves a state to the connected [`ShMem`], or a tmpfile, if its serialized size get too large.
    pub fn save<S>(&mut self, state: &S) -> Result<(), Error>
    where
        S: Serialize,
    {
        if self.has_content() {
            return Err(Error::illegal_state(
                "Trying to save state to a non-empty state map".to_string(),
            ));
        }

        let shmem_len = self.shmem.len();
        // Calculate available space: shmem.len() - sizeof(StateShMemContent)
        let available = shmem_len
            .checked_sub(size_of::<StateShMemContent>())
            .ok_or(Error::illegal_state("ShMem too small"))?;

        let content_ptr = self.header_mut_ptr();
        let payload_ptr = unsafe { content_ptr.cast::<u8>().add(size_of::<StateShMemContent>()) };
        let buf_slice = unsafe { slice::from_raw_parts_mut(payload_ptr, available) };

        // Try to serialize directly to shmem
        match postcard::to_slice(state, buf_slice) {
            Ok(bytes) => {
                // Success!
                let len = bytes.len();
                unsafe {
                    ptr::write_volatile(&raw mut (*content_ptr).is_disk, 0);
                    fence(Ordering::Release);
                    ptr::write_volatile(&raw mut (*content_ptr).buf_len, len);
                }
                Ok(())
            }
            Err(postcard::Error::SerializeBufferFull) => {
                // Buffer full, fall back to allocating vector and file (unsafe in signal handler usually, but best effort)
                let serialized = postcard::to_allocvec(state)?;
                // generate a filename
                let mut hasher = RandomState::with_seeds(0, 0, 0, 0).build_hasher();
                // Using the last few k as randomness for a filename, hoping it's unique.
                hasher.write(&serialized[serialized.len().saturating_sub(4096)..]);

                let filename = format!("{:016x}.libafl_state", hasher.finish());
                let tmpfile = temp_dir().join(&filename);
                File::create(tmpfile)?.write_all(&serialized)?;

                // write the filename to shmem
                let filename_buf = postcard::to_allocvec(&filename)?;

                let len = filename_buf.len();
                if len > available {
                    return Err(Error::illegal_state(format!(
                        "The state restorer map is too small to fit anything, even the filename! 
                            It needs to be at least {} bytes. 
                            The tmpfile was written to {}.",
                        len,
                        temp_dir().join(&filename).display()
                    )));
                }

                unsafe {
                    ptr::copy_nonoverlapping(filename_buf.as_ptr(), payload_ptr, len);
                    ptr::write_volatile(&raw mut (*content_ptr).is_disk, 1);
                    fence(Ordering::Release);
                    ptr::write_volatile(&raw mut (*content_ptr).buf_len, len);
                }
                Ok(())
            }
            Err(e) => Err(Error::serialize(format!("Postcard internal error: {e}"))),
        }
    }

    /// Reset this [`StateRestorer`] to an empty state.
    pub fn reset(&mut self) {
        if let Ok(Some(tmpfile)) = self.tmpfile() {
            // Remove tmpfile and ignore result
            drop(fs::remove_file(tmpfile));
        }
        if self.shmem.len() >= size_of::<StateShMemContent>() {
            let content_ptr = self.header_mut_ptr();
            unsafe {
                ptr::write_volatile(&raw mut (*content_ptr).buf_len, 0);
                ptr::write_volatile(&raw mut (*content_ptr).is_disk, 0);
                fence(Ordering::Release);
            }
        }
    }

    /// When called from a child, informs the restarter/parent process
    /// that it should no longer respawn the child.
    pub fn send_exiting(&mut self) {
        self.reset();

        let len = EXITING_MAGIC.len();

        assert!(size_of::<StateShMemContent>() + len <= self.shmem.len());

        let content_ptr = self.header_mut_ptr();
        // # Safety
        // `shmem` is verified above to hold `StateShMemContent` + `[u8; 16]`,
        // `[u8; 16]` has alignment 1, and `content_ptr` carries full map provenance.
        unsafe {
            let payload_ptr = content_ptr.cast::<u8>().add(size_of::<StateShMemContent>());
            ptr::write_volatile(payload_ptr.cast::<[u8; 16]>(), *EXITING_MAGIC);
            fence(Ordering::Release);
            ptr::write_volatile(&raw mut (*content_ptr).buf_len, len);
        }
    }

    /// Returns true, if [`Self::send_exiting`] was called on this [`StateRestorer`] last.
    /// This should be checked in the parent before deciding to restore the client.
    pub fn wants_to_exit(&self) -> bool {
        let len = EXITING_MAGIC.len();
        if self.shmem.len() < size_of::<StateShMemContent>() + len {
            return false;
        }
        let hdr = self.header_ptr();
        let buf_len = unsafe { ptr::read_volatile(&raw const (*hdr).buf_len) };
        fence(Ordering::Acquire);
        if buf_len != len || self.is_disk_unordered() {
            return false;
        }
        let magic = unsafe {
            ptr::read_volatile(
                self.shmem
                    .as_ptr()
                    .add(size_of::<StateShMemContent>())
                    .cast::<[u8; 16]>(),
            )
        };
        magic == *EXITING_MAGIC
    }

    /// Returns true, if this [`StateRestorer`] has contents.
    pub fn has_content(&self) -> bool {
        if self.shmem.len() < size_of::<StateShMemContent>() {
            return false;
        }
        let hdr = self.header_ptr();
        let buf_len = unsafe { ptr::read_volatile(&raw const (*hdr).buf_len) };
        fence(Ordering::Acquire);
        buf_len > 0
    }

    /// Restores the contents saved in this [`StateRestorer`], if any are available.
    /// Can only be read once.
    pub fn restore<S>(&self) -> Result<Option<S>, Error>
    where
        S: DeserializeOwned,
    {
        if self.shmem.len() < size_of::<StateShMemContent>() {
            return Ok(None);
        }
        let buf_len = self.buf_len_checked()?;
        if buf_len == 0 {
            return Ok(None);
        }
        let is_disk = self.is_disk_unordered();
        let bytes = unsafe {
            slice::from_raw_parts(
                self.shmem.as_ptr().add(size_of::<StateShMemContent>()),
                buf_len,
            )
        };

        if !is_disk && bytes == EXITING_MAGIC {
            return Err(Error::illegal_state(
                "Trying to restore a state after send_exiting was called.",
            ));
        }

        let mut state = bytes;
        let mut file_content;
        if is_disk {
            let filename: String = postcard::from_bytes(bytes)?;
            let tmpfile = temp_dir().join(&filename);
            file_content = vec![];
            File::open(&tmpfile)?.read_to_end(&mut file_content)?;
            if file_content.is_empty() {
                return Err(Error::illegal_state(format!(
                    "Could not restore state from file {filename}"
                )));
            }
            drop(fs::remove_file(&tmpfile));
            state = &file_content;
        }
        let deserialized = postcard::from_bytes(state)?;
        Ok(Some(deserialized))
    }
}

#[cfg(test)]
mod tests {

    #[cfg(not(target_os = "haiku"))]
    use serial_test::serial;

    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
    #[cfg(not(target_os = "haiku"))]
    fn test_state_restore() {
        use alloc::{
            string::{String, ToString},
            vec::Vec,
        };

        use crate::{
            shmem::{ShMemProvider, StdShMem, StdShMemProvider},
            staterestore::StateRestorer,
        };

        const TESTMAP_SIZE: usize = 1024;

        let mut shmem_provider = StdShMemProvider::new().unwrap();
        let shmem = shmem_provider.new_shmem(TESTMAP_SIZE).unwrap();
        let mut state_restorer = StateRestorer::<StdShMem, StdShMemProvider>::new(shmem);

        let state = "hello world".to_string();

        state_restorer.save(&state).unwrap();

        assert!(state_restorer.has_content());
        let restored = state_restorer.restore::<String>().unwrap().unwrap();
        log::info!("Restored {restored}");
        assert_eq!(restored, "hello world");
        assert!(!state_restorer.is_disk());

        state_restorer.reset();

        assert!(!state_restorer.has_content());
        assert!(!state_restorer.is_disk());
        assert!(state_restorer.restore::<String>().unwrap().is_none());

        let too_large = vec![4u8; TESTMAP_SIZE + 1];
        state_restorer.save(&too_large).unwrap();
        assert!(state_restorer.has_content());

        let large_restored = state_restorer.restore::<Vec<u8>>().unwrap().unwrap();
        assert_eq!(large_restored, too_large);
        assert_eq!(large_restored.len(), too_large.len());
        assert_eq!(large_restored[TESTMAP_SIZE], 4u8);

        assert!(state_restorer.is_disk());
        assert_ne!(state_restorer.buf_len_checked().unwrap(), 0);

        // Check if file removal works on restore.
        let tmpfile = state_restorer.tmpfile().unwrap().unwrap();
        assert!(!tmpfile.exists());

        state_restorer.reset();
        assert!(!state_restorer.has_content());
        assert!(!tmpfile.exists());

        // Check if file removal works on reset without restore.
        state_restorer.save(&too_large).unwrap();
        let tmpfile2 = state_restorer.tmpfile().unwrap().unwrap();
        assert!(tmpfile2.exists());
        state_restorer.reset();
        assert!(!state_restorer.has_content());
        assert!(!tmpfile2.exists());

        // Verify arbitrary non-boolean `is_disk` byte values (e.g., 0xFF) never trigger UB.
        state_restorer.shmem[0] = 0xFF;
        assert!(state_restorer.is_disk());
        state_restorer.reset();
        assert!(!state_restorer.is_disk());
    }

    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
    #[cfg(not(target_os = "haiku"))]
    fn test_state_restore_exiting() {
        use crate::{
            shmem::{ShMemProvider, StdShMem, StdShMemProvider},
            staterestore::StateRestorer,
        };

        const TESTMAP_SIZE: usize = 1024;

        let mut shmem_provider = StdShMemProvider::new().unwrap();
        let shmem = shmem_provider.new_shmem(TESTMAP_SIZE).unwrap();
        let mut state_restorer = StateRestorer::<StdShMem, StdShMemProvider>::new(shmem);

        assert!(!state_restorer.wants_to_exit());

        state_restorer.send_exiting();
        assert!(state_restorer.wants_to_exit());
        assert!(state_restorer.has_content());

        state_restorer.reset();
        assert!(!state_restorer.wants_to_exit());
        assert!(!state_restorer.has_content());
    }

    #[test]
    fn test_state_restorer_zero_and_corrupted_shmem_miri() {
        use alloc::string::String;

        use crate::{
            shmem::{NopShMem, NopShMemProvider, ShMemProvider},
            staterestore::StateRestorer,
        };

        let mut provider = NopShMemProvider::new().unwrap();
        // 0-byte and undersized maps must not dereference dangling pointers in `reset`/`has_content`/`save`.
        let mut empty_restorer =
            StateRestorer::<NopShMem, NopShMemProvider>::new(NopShMem::default());
        assert!(!empty_restorer.has_content() && !empty_restorer.wants_to_exit());
        assert!(!empty_restorer.is_disk());
        empty_restorer.reset();
        assert!(empty_restorer.save(&String::from("too small")).is_err());

        let mut tiny_restorer =
            StateRestorer::<NopShMem, NopShMemProvider>::new(provider.new_shmem(1).unwrap());
        assert!(!tiny_restorer.has_content());
        tiny_restorer.reset();

        let mut valid_restorer =
            StateRestorer::<NopShMem, NopShMemProvider>::new(provider.new_shmem(256).unwrap());
        valid_restorer.save(&String::from("miri state")).unwrap();
        assert_eq!(
            valid_restorer.restore::<String>().unwrap().as_deref(),
            Some("miri state")
        );
        valid_restorer.send_exiting();
        assert!(valid_restorer.wants_to_exit() && valid_restorer.restore::<String>().is_err());
        valid_restorer.shmem[0] = 0xFF;
        assert!(valid_restorer.is_disk() && !valid_restorer.wants_to_exit());

        // Corrupt `buf_len` to `usize::MAX`: `restore()` must return `Err` without OOB slice creation.
        let buf_len_off = core::mem::offset_of!(super::StateShMemContent, buf_len);
        valid_restorer.shmem[buf_len_off..buf_len_off + size_of::<usize>()]
            .copy_from_slice(&usize::MAX.to_ne_bytes());
        assert!(valid_restorer.restore::<String>().is_err());
    }
}
