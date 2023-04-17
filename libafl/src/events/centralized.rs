//! A very simple event manager, that just supports log outputs, but no multiprocessing

use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt::Debug, marker::PhantomData};

use super::{CustomBufEventResult, CustomBufHandlerFn, HasCustomBufHandlers, ProgressReporter};
use crate::{
    bolts::ClientId,
    events::{
        BrokerEventResult, Event, EventFirer, EventManager, EventManagerId, EventProcessor,
        EventRestarter, HasEventManagerId,
    },
    inputs::UsesInput,
    monitors::Monitor,
    state::{HasClientPerfMonitor, HasExecutions, HasMetadata, UsesState},
    Error,
};

/// The struct stored on the shared map, containing either the data, or the filename to read contents from.
#[repr(C)]
struct PointToPointShMemContent {
    buf_len: usize,
    buf: [u8; 0],
}

impl PointToPointShMemContent {
    /// Get a length that's safe to deref from this map, or error.
    pub fn buf_len_checked(&self, shmem_size: usize) -> Result<usize, Error> {
        let buf_len = unsafe { read_volatile(&self.buf_len) };
        if size_of::<PointToPointShMemContent>() + buf_len > shmem_size {
            Err(Error::illegal_state(format!("Stored buf_len is larger than the shared map! Shared data corrupted? Expected {shmem_size} bytes max, but got {} (buf_len {buf_len})", size_of::<PointToPointShMemContent>() + buf_len)))
        } else {
            Ok(buf_len)
        }
    }
}


#[derive(Debug, Clone)]
pub struct PointToPointSync<SP>
where
    SP: ShMemProvider,
{
    shmem: SP::ShMem,
    phantom: PhantomData<*const SP>,
}

impl<SP> PointToPointSync<SP>
where
    SP: ShMemProvider,
{
    /// Get the map size backing this [`PointToPointSync`].
    pub fn mapsize(&self) -> usize {
        self.shmem.len()
    }

    /// Writes this [`PointToPointSync`] to env variable, to be restored later
    pub fn write_to_env(&self, env_name: &str) -> Result<(), Error> {
        self.shmem.write_to_env(env_name)
    }

    /// Create a [`PointToPointSync`] from `env` variable name
    pub fn from_env(shmem_provider: &mut SP, env_name: &str) -> Result<Self, Error> {
        Ok(Self {
            shmem: shmem_provider.existing_from_env(env_name)?,
            phantom: PhantomData,
        })
    }

    /// Create a new [`PointToPointSync`].
    pub fn new(shmem: SP::ShMem) -> Self {
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

        let serialized = postcard::to_allocvec(state)?;

        if size_of::<PointToPointShMemContent>() + serialized.len() > self.shmem.len() {
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
            if len > self.shmem.len() {
                return Err(Error::illegal_state(format!(
                    "The state restorer map is too small to fit anything, even the filename! 
                        It needs to be at least {} bytes. 
                        The tmpfile was written to {:?}.",
                    len,
                    temp_dir().join(&filename)
                )));
            }

            /*log::info!(
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

    /// Reset this [`PointToPointSync`] to an empty state.
    pub fn reset(&mut self) {
        let mapsize = self.mapsize();
        let content_mut = self.content_mut();
        if let Ok(Some(tmpfile)) = content_mut.tmpfile(mapsize) {
            // Remove tmpfile and ignore result
            drop(fs::remove_file(tmpfile));
        }
        content_mut.is_disk = false;
        content_mut.buf_len = 0;
    }

    fn content_mut(&mut self) -> &mut PointToPointShMemContent {
        let ptr = self.shmem.as_slice().as_ptr();
        #[allow(clippy::cast_ptr_alignment)] // Beginning of the page will always be aligned
        unsafe {
            &mut *(ptr as *mut PointToPointShMemContent)
        }
    }

    /// The content is either the name of the tmpfile, or the serialized bytes directly, if they fit on a single page.
    fn content(&self) -> &PointToPointShMemContent {
        #[allow(clippy::cast_ptr_alignment)] // Beginning of the page will always be aligned
        let ptr = self.shmem.as_slice().as_ptr() as *const PointToPointShMemContent;
        unsafe { &*(ptr) }
    }

    /// Returns true, if this [`PointToPointSync`] has contents.
    pub fn has_content(&self) -> bool {
        self.content().buf_len > 0
    }

    /// Restores the contents saved in this [`PointToPointSync`], if any are available.
    /// Can only be read once.
    pub fn restore<S>(&self) -> Result<Option<S>, Error>
    where
        S: DeserializeOwned,
    {
        if !self.has_content() {
            return Ok(None);
        }
        let state_shmem_content = self.content();
        let bytes = unsafe {
            slice::from_raw_parts(
                state_shmem_content.buf.as_ptr(),
                state_shmem_content.buf_len_checked(self.mapsize())?,
            )
        };

        if bytes == EXITING_MAGIC {
            return Err(Error::illegal_state(
                "Trying to restore a state after send_exiting was called.",
            ));
        }

        let mut state = bytes;
        let mut file_content;
        if state_shmem_content.buf_len == 0 {
            return Ok(None);
        } else if state_shmem_content.is_disk {
            let filename: String = postcard::from_bytes(bytes)?;
            let tmpfile = temp_dir().join(&filename);
            file_content = vec![];
            File::open(tmpfile)?.read_to_end(&mut file_content)?;
            if file_content.is_empty() {
                return Err(Error::illegal_state(format!(
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


/// A simple, single-threaded event manager that just logs
#[derive(Debug)]
pub struct CentralizedEventManager<EM, S>
where
    S: UsesInput,
{
    inner: EM,
    phantom: PhantomData<S>,
}

impl<EM, S> UsesState for CentralizedEventManager<EM, S>
where
    S: UsesInput,
{
    type State = S;
}

impl<EM, S> EventFirer for CentralizedEventManager<EM, S>
where
    EM: EventFirer,
    S: UsesInput,
{
    fn fire(
        &mut self,
        _state: &mut Self::State,
        event: Event<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        match Self::handle_in_broker(&mut self.monitor, &event)? {
            BrokerEventResult::Forward => self.events.push(event),
            BrokerEventResult::Handled => (),
        };
        Ok(())
    }

    fn log(
        &mut self,
        state: &mut Self::State,
        severity_level: LogSeverity,
        message: String,
    ) -> Result<(), Error> {
        self.inner.log(state, severity_level, message)
    }

    fn serialize_observers<OT>(&mut self, observers: &OT) -> Result<Vec<u8>, Error>
    where
        OT: ObserversTuple<Self::State> + Serialize,
    {
        self.inner.serialize_observers(observers)
    }

    fn configuration(&self) -> EventConfig {
        self.inner.configuration()
    }
}

impl<EM, S> EventRestarter for CentralizedEventManager<EM, S>
where
    EM: EventRestarter,
    S: UsesInput,
{
    #[inline]
    fn on_restart(&mut self, state: &mut Self::State) -> Result<(), Error> {
        self.inner.on_restart(state)
    }

    fn send_exiting(&mut self) -> Result<(), Error> {
        self.inner.send_exiting()
    }

    #[inline]
    fn await_restart_safe(&mut self) {
        self.inner.await_restart_safe()
    }
}

impl<E, EM, S, Z> EventProcessor<E, Z> for CentralizedEventManager<EM, S>
where
    EM: EventProcessor<E, Z>,
    S: UsesInput,
{
    fn process(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _executor: &mut E,
    ) -> Result<usize, Error> {
        let count = self.events.len();
        while !self.events.is_empty() {
            let event = self.events.pop().unwrap();
            self.handle_in_client(state, event)?;
        }
        Ok(count)
    }
}

impl<E, EM, S, Z> EventManager<E, Z> for CentralizedEventManager<EM, S>
where
    EM: EventManager<E, Z>,
    S: UsesInput + HasClientPerfMonitor + HasExecutions + HasMetadata,
{
}

impl<EM, S> HasCustomBufHandlers for CentralizedEventManager<EM, S>
where
    EM: HasCustomBufHandlers,
    S: UsesInput,
{
    /// Adds a custom buffer handler that will run for each incoming `CustomBuf` event.
    fn add_custom_buf_handler(
        &mut self,
        handler: Box<
            dyn FnMut(&mut Self::State, &String, &[u8]) -> Result<CustomBufEventResult, Error>,
        >,
    ) {
        self.custom_buf_handlers.push(handler);
    }
}

impl<EM, S> ProgressReporter for CentralizedEventManager<EM, S>
where
    EM: ProgressReporter,
    S: UsesInput + HasExecutions + HasClientPerfMonitor + HasMetadata,
{
}

impl<EM, S> HasEventManagerId for CentralizedEventManager<EM, S>
where
    EM: HasEventManagerId,
    S: UsesInput,
{
    fn mgr_id(&self) -> EventManagerId {
        self.inner.mgr_id()
    }
}

impl<EM, S> CentralizedEventManager<EM, S>
where
    S: UsesInput,
{
    /// Creates a new [`CentralizedEventManager`].
    pub fn new(inner: EM) -> Self {
        Self {
            inner,
            phantom: PhantomData,
        }
    }
}
