/// Stores and restores state when a client needs to relaunch.
/// Uses a [`ShMem`] up to a threshold, then write to disk.
use ahash::AHasher;
use core::{hash::Hasher, marker::PhantomData, mem::size_of, ptr, slice};
use postcard;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    env::temp_dir,
    fs::File,
    io::{Read, Write},
};

use crate::{
    bolts::shmem::{ShMem, ShMemProvider},
    Error,
};

/// A [`StateRestorer`] saves and restores bytes to a shared map.
/// If the state gets larger than the preallocated [`ShMem`] shared map,
/// it will instead write to disk, and store the file name into the map.
/// Writing to [`StateRestorer`] multiple times is not allowed.
#[derive(Debug, Clone)]
pub struct StateRestorer<SP>
where
    SP: ShMemProvider,
{
    shmem: SP::Mem,
    phantom: PhantomData<*const SP>,
}

#[repr(C)]
struct StateShMemContent {
    is_disk: bool,
    buf_len: usize,
    buf: [u8; 0],
}

impl<SP> StateRestorer<SP>
where
    SP: ShMemProvider,
{
    /// Writes this [`StateRestorer`] to env variable, to be restored later
    pub fn write_to_env(&self, env_name: &str) -> Result<(), Error> {
        self.shmem.write_to_env(env_name)
    }

    /// Create a [`StateRrestore`] from `env` variable name
    pub fn from_env(shmem_provider: &mut SP, env_name: &str) -> Result<Self, Error> {
        Ok(Self {
            shmem: shmem_provider.existing_from_env(env_name)?,
            phantom: PhantomData,
        })
    }

    /// Create a new [`StateRestorer`].
    pub fn new(shmem: SP::Mem) -> Self {
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
            return Err(Error::IllegalState(
                "Trying to save state to a non-empty state map".to_string(),
            ));
        }

        let serialized = postcard::to_allocvec(state)?;

        if size_of::<StateShMemContent>() + serialized.len() > self.shmem.len() {
            // generate a filename
            let mut hasher = AHasher::new_with_keys(0, 0);
            hasher.write(&serialized[serialized.len() - 1024..]);

            let filename = format!("{:016x}.libafl_state", hasher.finish());
            let tmpfile = temp_dir().join(&filename);
            File::create(tmpfile)?.write_all(&serialized)?;

            // write the filename to shmem
            let filename_buf = postcard::to_allocvec(&filename)?;

            let len = filename_buf.len();
            if len > self.shmem.len() {
                return Err(Error::IllegalState(
                    format!(
                        "The state restorer map is too small to fit anything, even the filename! 
                        It needs to be at least {} bytes. 
                        The tmpfile was written to {:?}.",
                        len,
                        temp_dir().join(&filename)
                    )
                    .to_string(),
                ));
            }

            /*println!(
                "Storing {} bytes to tmpfile {} (larger than map of {} bytes)",
                serialized.len(),
                &filename,
                self.shmem.len()
            );*/

            let shmem_content = self.content_mut();
            unsafe {
                ptr::copy_nonoverlapping(
                    filename_buf.as_ptr() as *const u8,
                    shmem_content.buf.as_mut_ptr(),
                    len,
                );
            }
            shmem_content.buf_len = len;
            shmem_content.is_disk = true;
        } else {
            // write to shmem directly
            let len = serialized.len();
            let shmem_content = self.content_mut();
            unsafe {
                ptr::copy_nonoverlapping(
                    serialized.as_ptr() as *const u8,
                    shmem_content.buf.as_mut_ptr(),
                    len,
                );
            }
            shmem_content.buf_len = len;
            shmem_content.is_disk = false;
        };
        Ok(())
    }

    /// Reset this [`StateRestorer`] to an empty state.
    pub fn reset(&mut self) {
        let content_mut = self.content_mut();
        content_mut.is_disk = false;
        content_mut.buf_len = 0;
    }

    fn content_mut(&mut self) -> &mut StateShMemContent {
        let ptr = self.shmem.map().as_ptr();
        #[allow(clippy::cast_ptr_alignment)] // Beginning of the page will always be aligned
        unsafe {
            &mut *(ptr as *mut StateShMemContent)
        }
    }

    /// The content is either the name of the tmpfile, or the serialized bytes directly, if they fit on a single page.
    fn content(&self) -> &StateShMemContent {
        #[allow(clippy::cast_ptr_alignment)] // Beginning of the page will always be aligned
        let ptr = self.shmem.map().as_ptr() as *const StateShMemContent;
        unsafe { &*(ptr) }
    }

    /// Returns true, if this [`StateRestorer`] has contents.
    pub fn has_content(&self) -> bool {
        self.content().buf_len > 0
    }

    /// Restores the contents saved in this [`StateRestorer`], if any are availiable.
    pub fn restore<S>(&self) -> Result<Option<S>, Error>
    where
        S: DeserializeOwned,
    {
        if !self.has_content() {
            return Ok(Option::None);
        }
        let state_shmem_content = self.content();
        let bytes = unsafe {
            slice::from_raw_parts(
                state_shmem_content.buf.as_ptr(),
                state_shmem_content.buf_len,
            )
        };
        let mut state = bytes;
        let mut file_content;
        if state_shmem_content.buf_len == 0 {
            return Ok(Option::None);
        } else if state_shmem_content.is_disk {
            let filename: String = postcard::from_bytes(bytes)?;
            let tmpfile = temp_dir().join(&filename);
            file_content = vec![];
            File::open(tmpfile)?.read_to_end(&mut file_content)?;
            if file_content.is_empty() {
                return Err(Error::IllegalState(format!(
                    "Colud not restore state from file {}",
                    &filename
                )));
            }
            state = &file_content;
        }
        let deserialized = postcard::from_bytes(state)?;
        Ok(Some(deserialized))
    }
}

#[cfg(test)]
mod tests {
    use crate::bolts::shmem::{ShMemProvider, StdShMemProvider};

    use super::StateRestorer;

    #[test]
    fn test_state_restore() {
        const TESTMAP_SIZE: usize = 1024;

        let mut shmem_provider = StdShMemProvider::new().unwrap();
        let shmem = shmem_provider.new_map(TESTMAP_SIZE).unwrap();
        let mut state_restorer = StateRestorer::<StdShMemProvider>::new(shmem);

        let state = "hello world".to_string();

        state_restorer.save(&state).unwrap();

        assert!(state_restorer.has_content());
        let restored = state_restorer.restore::<String>().unwrap().unwrap();
        println!("Restored {}", restored);
        assert_eq!(restored, "hello world");

        state_restorer.reset();

        assert!(!state_restorer.has_content());
        assert!(state_restorer.restore::<String>().unwrap().is_none());

        let too_large = vec![4u8; TESTMAP_SIZE + 1];
        state_restorer.save(&too_large).unwrap();
        assert!(state_restorer.has_content());

        let large_restored = state_restorer.restore::<Vec<u8>>().unwrap().unwrap();
        assert_eq!(large_restored, too_large);
        assert_eq!(large_restored.len(), too_large.len());
        assert_eq!(large_restored[TESTMAP_SIZE], 4u8);
    }
}
