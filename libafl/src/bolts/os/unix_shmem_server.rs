/*!
On `Android`, we can only share maps between processes by serializing fds over sockets.
On `MacOS`, we cannot rely on reference counting for Maps.
Hence, the `unix_shmem_server` keeps track of existing maps, creates new maps for clients,
and forwards them over unix domain sockets.
*/

#[cfg(feature = "std")]
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{mem::ManuallyDrop, ptr::addr_of};
#[cfg(target_vendor = "apple")]
use std::fs;
use std::{
    cell::RefCell,
    env,
    io::{Read, Write},
    marker::PhantomData,
    rc::{Rc, Weak},
    sync::{Arc, Condvar, Mutex},
    thread::JoinHandle,
};
#[cfg(all(feature = "std", unix))]
use std::{
    os::unix::{
        io::{AsRawFd, RawFd},
        net::{UnixListener, UnixStream},
    },
    thread,
};

use hashbrown::HashMap;
#[cfg(all(feature = "std", unix))]
use nix::poll::{poll, PollFd, PollFlags};
use serde::{Deserialize, Serialize};
#[cfg(all(unix, feature = "std"))]
use uds::{UnixListenerExt, UnixSocketAddr, UnixStreamExt};

use crate::{
    bolts::{
        shmem::{ShMem, ShMemDescription, ShMemId, ShMemProvider},
        AsMutSlice, AsSlice,
    },
    Error,
};

/// The default server name for our abstract shmem server
#[cfg(all(unix, not(target_vendor = "apple")))]
const UNIX_SERVER_NAME: &str = "@libafl_unix_shmem_server";
/// `MacOS` server name is on disk, since `MacOS` doesn't support abtract domain sockets.
#[cfg(target_vendor = "apple")]
const UNIX_SERVER_NAME: &str = "./libafl_unix_shmem_server";

/// Env variable. If set, we won't try to spawn the service
const AFL_SHMEM_SERVICE_STARTED: &str = "AFL_SHMEM_SERVICE_STARTED";

/// Hands out served shared maps, as used on Android.
#[derive(Debug)]
pub struct ServedShMemProvider<SP>
where
    SP: ShMemProvider,
{
    stream: UnixStream,
    inner: SP,
    id: i32,
    /// A referencde to the [`ShMemService`] backing this provider.
    /// It will be started only once for all processes and providers.
    service: ShMemService<SP>,
}

/// [`ShMem`] that got served from a [`ShMemService`] via domain sockets and can now be used in this program.
/// It works around Android's lack of "proper" shared maps.
#[derive(Clone, Debug)]
pub struct ServedShMem<SH>
where
    SH: ShMem,
{
    inner: ManuallyDrop<SH>,
    server_fd: i32,
}

impl<SH> ShMem for ServedShMem<SH>
where
    SH: ShMem,
{
    fn id(&self) -> ShMemId {
        let client_id = self.inner.id();
        ShMemId::from_string(&format!("{}:{client_id}", self.server_fd))
    }

    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<SH> AsSlice for ServedShMem<SH>
where
    SH: ShMem,
{
    type Entry = u8;
    fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }
}
impl<SH> AsMutSlice for ServedShMem<SH>
where
    SH: ShMem,
{
    type Entry = u8;
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.inner.as_mut_slice()
    }
}

impl<SP> ServedShMemProvider<SP>
where
    SP: ShMemProvider,
{
    /// Send a request to the server, and wait for a response
    #[allow(clippy::similar_names)] // id and fd
    fn send_receive(&mut self, request: ServedShMemRequest) -> Result<(i32, i32), Error> {
        //let bt = Backtrace::new();
        //println!("Sending {:?} with bt:\n{:?}", request, bt);

        let body = postcard::to_allocvec(&request)?;

        let header = (body.len() as u32).to_be_bytes();
        let mut message = header.to_vec();
        message.extend(body);

        self.stream
            .write_all(&message)
            .expect("Failed to send message");

        let mut shm_slice = [0_u8; 20];
        let mut fd_buf = [-1; 1];
        self.stream
            .recv_fds(&mut shm_slice, &mut fd_buf)
            .expect("Did not receive a response");

        let server_id = ShMemId::from_array(&shm_slice);
        let server_fd: i32 = server_id.into();
        Ok((server_fd, fd_buf[0]))
    }
}

impl<SP> Default for ServedShMemProvider<SP>
where
    SP: ShMemProvider,
{
    fn default() -> Self {
        Self::new().unwrap()
    }
}

impl<SP> Clone for ServedShMemProvider<SP>
where
    SP: ShMemProvider,
{
    fn clone(&self) -> Self {
        let mut cloned = Self::new().unwrap();
        cloned.service = self.service.clone();
        cloned
    }
}

impl<SP> ShMemProvider for ServedShMemProvider<SP>
where
    SP: ShMemProvider,
{
    type ShMem = ServedShMem<SP::ShMem>;

    /// Connect to the server and return a new [`ServedShMemProvider`]
    /// Will try to spawn a [`ShMemService`]. This will only work for the first try.
    fn new() -> Result<Self, Error> {
        // Needed for MacOS and Android to get sharedmaps working.
        let service = ShMemService::<SP>::start();

        let mut res = Self {
            stream: UnixStream::connect_to_unix_addr(&UnixSocketAddr::new(UNIX_SERVER_NAME)?)?,
            inner: SP::new()?,
            id: -1,
            service,
        };
        let (id, _) = res.send_receive(ServedShMemRequest::Hello())?;
        res.id = id;
        Ok(res)
    }

    fn new_shmem(&mut self, map_size: usize) -> Result<Self::ShMem, Error> {
        let (server_fd, client_fd) = self.send_receive(ServedShMemRequest::NewMap(map_size))?;

        Ok(ServedShMem {
            inner: ManuallyDrop::new(
                self.inner.shmem_from_id_and_size(
                    ShMemId::from_string(&format!("{client_fd}")),
                    map_size,
                )?,
            ),
            server_fd,
        })
    }

    fn shmem_from_id_and_size(&mut self, id: ShMemId, size: usize) -> Result<Self::ShMem, Error> {
        let parts = id.as_str().split(':').collect::<Vec<&str>>();
        let server_id_str = parts.first().unwrap();
        let (server_fd, client_fd) = self.send_receive(ServedShMemRequest::ExistingMap(
            ShMemDescription::from_string_and_size(server_id_str, size),
        ))?;
        Ok(ServedShMem {
            inner: ManuallyDrop::new(
                self.inner
                    .shmem_from_id_and_size(ShMemId::from_string(&format!("{client_fd}")), size)?,
            ),
            server_fd,
        })
    }

    fn pre_fork(&mut self) -> Result<(), Error> {
        self.send_receive(ServedShMemRequest::PreFork())?;
        Ok(())
    }

    fn post_fork(&mut self, is_child: bool) -> Result<(), Error> {
        if is_child {
            // After fork, only the parent keeps the join handle.
            if let ShMemService::Started { bg_thread, .. } = &self.service {
                bg_thread.lock().unwrap().join_handle = None;
            }
            //fn connect(&mut self) -> Result<Self, Error> {
            //self.stream = UnixStream::connect_to_unix_addr(&UnixSocketAddr::new(UNIX_SERVER_NAME)?)?,

            // After fork, the child needs to reconnect as to not share the fds with the parent.
            self.stream =
                UnixStream::connect_to_unix_addr(&UnixSocketAddr::new(UNIX_SERVER_NAME)?)?;
            let (id, _) = self.send_receive(ServedShMemRequest::PostForkChildHello(self.id))?;
            self.id = id;
        }
        Ok(())
    }

    fn release_shmem(&mut self, map: &mut Self::ShMem) {
        let (refcount, _) = self
            .send_receive(ServedShMemRequest::Deregister(map.server_fd))
            .expect("Could not communicate with ServedShMem server!");
        if refcount == 1 {
            unsafe {
                ManuallyDrop::drop(&mut map.inner);
            }
        }
    }
}

/// A request sent to the [`ShMem`] server to receive a fd to a shared map
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum ServedShMemRequest {
    /// Register a new map with a given size.
    NewMap(usize),
    /// Another client already has a map with this description mapped.
    ExistingMap(ShMemDescription),
    /// A client tells us it unregisters the previously allocated map
    Deregister(i32),
    /// A message that tells us hello, and optionally which other client we were created from, we
    /// return a client id.
    Hello(),
    /// A client tells us that it's about to fork. Already clone all of the maps now so that they will be available by the time the child sends a [`ServedShMemRequest::PostForkChildHello`] request.
    PreFork(),
    /// The client's child re-registers with us after it forked.
    PostForkChildHello(i32),
    /// The ShMem Service should exit. This is sually sent internally on `drop`, but feel free to do whatever with it?
    Exit,
}

/// Client side communicating with the [`ShMemServer`]
#[derive(Debug)]
struct SharedShMemClient<SH>
where
    SH: ShMem,
{
    stream: UnixStream,
    maps: HashMap<i32, Vec<Rc<RefCell<SH>>>>,
}

impl<SH> SharedShMemClient<SH>
where
    SH: ShMem,
{
    fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            maps: HashMap::new(),
        }
    }
}

/// Response from Server to Client
#[derive(Debug)]
enum ServedShMemResponse<SP>
where
    SP: ShMemProvider,
{
    Mapping(Rc<RefCell<SP::ShMem>>),
    Id(i32),
    RefCount(u32),
}

/// Report the status of the [`ShMem`] background thread start status
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShMemServiceStatus {
    Starting,
    Started,
    Failed,
}

/// The [`ShMemService`] is a service handing out [`ShMem`] pages via unix domain sockets.
/// It is mainly used and needed on Android.
#[derive(Debug, Clone)]
pub enum ShMemService<SP>
where
    SP: ShMemProvider,
{
    /// A started service
    Started {
        /// The background thread
        bg_thread: Arc<Mutex<ShMemServiceThread>>,
        /// The pantom data
        phantom: PhantomData<SP>,
    },
    /// A failed service
    Failed {
        /// The error message
        err_msg: String,
        /// The pantom data
        phantom: PhantomData<SP>,
    },
}

/// Wrapper for the service background thread.
/// When this is dropped, the background thread will get killed and joined.
#[derive(Debug)]
pub struct ShMemServiceThread {
    join_handle: Option<JoinHandle<Result<(), Error>>>,
}

impl Drop for ShMemServiceThread {
    fn drop(&mut self) {
        if self.join_handle.is_some() {
            println!("Stopping ShMemService");
            let mut stream = match UnixStream::connect_to_unix_addr(
                &UnixSocketAddr::new(UNIX_SERVER_NAME).unwrap(),
            ) {
                Ok(stream) => stream,
                Err(_) => return, // ignoring non-started server
            };

            let body = postcard::to_allocvec(&ServedShMemRequest::Exit).unwrap();

            let header = (body.len() as u32).to_be_bytes();
            let mut message = header.to_vec();
            message.extend(body);

            stream
                .write_all(&message)
                .expect("Failed to send bye-message to ShMemService");
            self.join_handle
                .take()
                .unwrap()
                .join()
                .expect("Failed to join ShMemService thread!")
                .expect("Error in ShMemService background thread!");
            // try to remove the file from fs, and ignore errors.
            #[cfg(target_vendor = "apple")]
            fs::remove_file(UNIX_SERVER_NAME).unwrap();

            env::remove_var(AFL_SHMEM_SERVICE_STARTED);
        }
    }
}

impl<SP> ShMemService<SP>
where
    SP: ShMemProvider,
{
    /// Create a new [`ShMemService`], then listen and service incoming connections in a new thread.
    /// Returns [`ShMemService::Failed`] on error.
    #[must_use]
    pub fn start() -> Self {
        // Already running, no need to spawn additional thraeds anymore.
        if env::var(AFL_SHMEM_SERVICE_STARTED).is_ok() {
            return Self::Failed {
                err_msg: "ShMemService already started".to_string(),
                phantom: PhantomData,
            };
        }

        #[allow(clippy::mutex_atomic)]
        let syncpair = Arc::new((Mutex::new(ShMemServiceStatus::Starting), Condvar::new()));
        let childsyncpair = Arc::clone(&syncpair);
        let join_handle = thread::spawn(move || {
            let mut worker = match ServedShMemServiceWorker::<SP>::new() {
                Ok(worker) => worker,
                Err(e) => {
                    // Make sure the parent processes can continue
                    let (lock, cvar) = &*childsyncpair;
                    *lock.lock().unwrap() = ShMemServiceStatus::Failed;
                    cvar.notify_one();

                    println!("Error creating ShMemService: {e:?}");
                    return Err(e);
                }
            };
            if let Err(e) = worker.listen(UNIX_SERVER_NAME, &childsyncpair) {
                println!("Error spawning ShMemService: {e:?}");
                Err(e)
            } else {
                Ok(())
            }
        });

        let (lock, cvar) = &*syncpair;
        let mut success = lock.lock().unwrap();
        while *success == ShMemServiceStatus::Starting {
            success = cvar.wait(success).unwrap();
        }

        // Optimization: Following calls or even child processe don't need to try to start a service anymore.
        // It's either running at this point, or we won't be able to spawn it anyway.
        env::set_var(AFL_SHMEM_SERVICE_STARTED, "true");

        let status = *success;
        match status {
            ShMemServiceStatus::Starting => panic!("Unreachable"),
            ShMemServiceStatus::Started => {
                println!("Started ShMem Service");
                // We got a service
                Self::Started {
                    bg_thread: Arc::new(Mutex::new(ShMemServiceThread {
                        join_handle: Some(join_handle),
                    })),
                    phantom: PhantomData,
                }
            }
            ShMemServiceStatus::Failed => {
                // We ignore errors as multiple threads may call start.
                let err = join_handle.join();
                let err = err.expect("Failed to join ShMemService thread!");
                let err = err.expect_err("Expected service start to have failed, but it didn't?");

                Self::Failed {
                    err_msg: format!("{err}"),
                    phantom: PhantomData,
                }
            }
        }
    }
}

/// The struct for the worker, handling incoming requests for [`ShMem`].
#[allow(clippy::type_complexity)]
struct ServedShMemServiceWorker<SP>
where
    SP: ShMemProvider,
{
    provider: SP,
    clients: HashMap<RawFd, SharedShMemClient<SP::ShMem>>,
    /// Maps from a pre-fork (parent) client id to its cloned maps.
    forking_clients: HashMap<RawFd, HashMap<i32, Vec<Rc<RefCell<SP::ShMem>>>>>,
    all_shmems: HashMap<i32, Weak<RefCell<SP::ShMem>>>,
}

impl<SP> ServedShMemServiceWorker<SP>
where
    SP: ShMemProvider,
{
    /// Create a new [`ShMemService`]
    fn new() -> Result<Self, Error> {
        Ok(Self {
            provider: SP::new()?,
            clients: HashMap::new(),
            all_shmems: HashMap::new(),
            forking_clients: HashMap::new(),
        })
    }

    fn upgrade_shmem_with_id(&mut self, description_id: i32) -> Rc<RefCell<SP::ShMem>> {
        self.all_shmems
            .get_mut(&description_id)
            .unwrap()
            .clone()
            .upgrade()
            .unwrap()
    }

    /// Read and handle the client request, send the answer over unix fd.
    fn handle_request(&mut self, client_id: RawFd) -> Result<ServedShMemResponse<SP>, Error> {
        let request = self.read_request(client_id)?;

        // println!("got ashmem client: {}, request:{:?}", client_id, request);

        // Handle the client request
        let response = match request {
            ServedShMemRequest::Hello() => Ok(ServedShMemResponse::Id(client_id)),
            ServedShMemRequest::PreFork() => {
                // We clone the provider already, waiting for it to reconnect [`PostFork`].
                // That wa, even if the parent dies before the child sends its `PostFork`, we should be good.
                // See issue https://github.com/AFLplusplus/LibAFL/issues/276
                //let forking_client = self.clients[&client_id].maps.clone();
                self.forking_clients
                    .insert(client_id, self.clients[&client_id].maps.clone());
                // Technically, no need to send the client_id here but it keeps the code easier.

                /*
                // remove temporarily
                let client = self.clients.remove(&client_id);
                let mut forking_shmems = HashMap::new();
                for (id, map) in client.as_ref().unwrap().maps.iter() {
                    forking_shmems.insert(*id, map.clone());
                }
                self.forking_clients.insert(client_id, forking_shmems);
                self.clients.insert(client_id, client.unwrap());
                */

                Ok(ServedShMemResponse::Id(client_id))
            }
            ServedShMemRequest::PostForkChildHello(other_id) => {
                let client = self.clients.get_mut(&client_id).unwrap();
                client.maps = self.forking_clients.remove(&other_id).unwrap();
                Ok(ServedShMemResponse::Id(client_id))
            }
            ServedShMemRequest::NewMap(map_size) => {
                let new_shmem = self.provider.new_shmem(map_size)?;
                let description = new_shmem.description();
                let new_rc = Rc::new(RefCell::new(new_shmem));
                self.all_shmems
                    .insert(description.id.into(), Rc::downgrade(&new_rc));
                Ok(ServedShMemResponse::Mapping(new_rc))
            }
            ServedShMemRequest::ExistingMap(description) => {
                let client = self.clients.get_mut(&client_id).unwrap();
                let description_id: i32 = description.id.into();
                if client.maps.contains_key(&description_id) {
                    // Using let else here as self needs to be accessed in the else branch.
                    #[allow(clippy::option_if_let_else)]
                    Ok(ServedShMemResponse::Mapping(
                        if let Some(map) = client
                            .maps
                            .get_mut(&description_id)
                            .as_mut()
                            .unwrap()
                            .first()
                            .as_mut()
                        {
                            map.clone()
                        } else {
                            self.upgrade_shmem_with_id(description_id)
                        },
                    ))
                } else {
                    Ok(ServedShMemResponse::Mapping(
                        self.upgrade_shmem_with_id(description_id),
                    ))
                }
            }
            ServedShMemRequest::Deregister(map_id) => {
                let client = self.clients.get_mut(&client_id).unwrap();
                let maps = client.maps.entry(map_id).or_default();
                if maps.is_empty() {
                    Ok(ServedShMemResponse::RefCount(0_u32))
                } else {
                    Ok(ServedShMemResponse::RefCount(
                        Rc::strong_count(&maps.pop().unwrap()) as u32,
                    ))
                }
            }
            ServedShMemRequest::Exit => {
                println!("ShMemService - Exiting");
                // stopping the server
                return Err(Error::shutting_down());
            }
        };
        // println!("send ashmem client: {}, response: {:?}", client_id, &response);

        response
    }

    fn read_request(&mut self, client_id: RawFd) -> Result<ServedShMemRequest, Error> {
        let client = self.clients.get_mut(&client_id).unwrap();

        // Always receive one be u32 of size, then the command.
        let mut size_bytes = [0_u8; 4];
        client.stream.read_exact(&mut size_bytes)?;
        let size = u32::from_be_bytes(size_bytes);
        let mut bytes = vec![];
        bytes.resize(size as usize, 0_u8);
        client
            .stream
            .read_exact(&mut bytes)
            .expect("Failed to read message body");
        let request: ServedShMemRequest = postcard::from_bytes(&bytes)?;

        Ok(request)
    }
    fn handle_client(&mut self, client_id: RawFd) -> Result<(), Error> {
        let response = self.handle_request(client_id)?;

        match response {
            ServedShMemResponse::Mapping(mapping) => {
                let id = mapping.as_ref().borrow().id();
                let server_fd: i32 = id.to_string().parse().unwrap();
                let client = self.clients.get_mut(&client_id).unwrap();
                client
                    .stream
                    .send_fds(id.to_string().as_bytes(), &[server_fd])?;
                client.maps.entry(server_fd).or_default().push(mapping);
            }
            ServedShMemResponse::Id(id) => {
                let client = self.clients.get_mut(&client_id).unwrap();
                client.stream.send_fds(id.to_string().as_bytes(), &[])?;
            }
            ServedShMemResponse::RefCount(refcount) => {
                let client = self.clients.get_mut(&client_id).unwrap();
                client
                    .stream
                    .send_fds(refcount.to_string().as_bytes(), &[])?;
            }
        }
        Ok(())
    }

    /// Listen on a filename (or abstract name) for new connections and serve them. This function
    /// should not return.
    fn listen(
        &mut self,
        filename: &str,
        syncpair: &Arc<(Mutex<ShMemServiceStatus>, Condvar)>,
    ) -> Result<(), Error> {
        let listener = match UnixListener::bind_unix_addr(&UnixSocketAddr::new(filename)?) {
            Ok(listener) => listener,
            Err(err) => {
                let (lock, cvar) = &**syncpair;
                *lock.lock().unwrap() = ShMemServiceStatus::Failed;
                cvar.notify_one();

                return Err(Error::unknown(format!(
                    "The ShMem server appears to already be running. We are probably a client. Error: {err:?}")));
            }
        };

        let mut poll_fds: Vec<PollFd> = vec![PollFd::new(
            listener.as_raw_fd(),
            PollFlags::POLLIN | PollFlags::POLLRDNORM | PollFlags::POLLRDBAND,
        )];

        let (lock, cvar) = &**syncpair;
        *lock.lock().unwrap() = ShMemServiceStatus::Started;
        cvar.notify_one();

        loop {
            match poll(&mut poll_fds, -1) {
                Ok(num_fds) if num_fds > 0 => (),
                Ok(_) => continue,
                Err(e) => {
                    println!("Error polling for activity: {e:?}");
                    continue;
                }
            };
            let copied_poll_fds: Vec<PollFd> = poll_fds.clone();
            for poll_fd in copied_poll_fds {
                let revents = poll_fd.revents().expect("revents should not be None");
                let raw_polled_fd = unsafe { *((addr_of!(poll_fd)) as *const libc::pollfd) }.fd;
                if revents.contains(PollFlags::POLLHUP) {
                    poll_fds.remove(poll_fds.iter().position(|item| *item == poll_fd).unwrap());
                    self.clients.remove(&raw_polled_fd);
                } else if revents.contains(PollFlags::POLLIN) {
                    if self.clients.contains_key(&raw_polled_fd) {
                        match self.handle_client(raw_polled_fd) {
                            Ok(()) => (),
                            Err(e) => {
                                dbg!("Ignoring failed read from client", e, poll_fd);
                                continue;
                            }
                        };
                    } else {
                        let (stream, _addr) = match listener.accept_unix_addr() {
                            Ok(stream_val) => stream_val,
                            Err(e) => {
                                println!("Error accepting client: {e:?}");
                                continue;
                            }
                        };

                        println!("Recieved connection from {_addr:?}");
                        let pollfd = PollFd::new(
                            stream.as_raw_fd(),
                            PollFlags::POLLIN | PollFlags::POLLRDNORM | PollFlags::POLLRDBAND,
                        );
                        poll_fds.push(pollfd);
                        let client = SharedShMemClient::new(stream);
                        let client_id = client.stream.as_raw_fd();
                        self.clients.insert(client_id, client);
                        match self.handle_client(client_id) {
                            Ok(()) => (),
                            Err(Error::ShuttingDown) => {
                                println!("Shutting down");
                                return Ok(());
                            }
                            Err(e) => {
                                dbg!("Ignoring failed read from client", e);
                            }
                        };
                    }
                } else {
                    //println!("Unknown revents flags: {:?}", revents);
                }
            }
        }
    }
}

/*
TODO: Fix test

#[cfg(test)]
mod tests {
    use serial_test::serial;

    use crate::bolts::{
        os::unix_shmem_server::ServedShMemProvider,
        shmem::{ShMem, ShMemProvider, UnixShMemProvider},
    };

    #[test]
    #[serial]
    fn test_shmem_server_connection() {
        let mut sp = ServedShMemProvider::<UnixShMemProvider>::new().unwrap();
        let map = sp.new_shmem(2 << 14).unwrap();
        assert!(map.is_empty());
    }
}
*/
