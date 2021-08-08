/*!
On `Android`, we can only share maps between processes by serializing fds over sockets.
On `MacOS`, we cannot rely on reference counting for Maps.
Hence, the `unix_shmem_server` keeps track of existing maps, creates new maps for clients,
and forwards them over unix domain sockets.
*/

use crate::{
    bolts::shmem::{ShMem, ShMemDescription, ShMemId, ShMemProvider},
    Error,
};
use core::mem::ManuallyDrop;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use std::{
    borrow::BorrowMut,
    cell::RefCell,
    io::{Read, Write},
    marker::PhantomData,
    rc::{Rc, Weak},
    sync::{Arc, Condvar, Mutex},
    thread::JoinHandle,
};

#[cfg(any(target_os = "macos", target_os = "ios"))]
use std::fs;

#[cfg(all(feature = "std", unix))]
use nix::poll::{poll, PollFd, PollFlags};

#[cfg(all(feature = "std", unix))]
use std::{
    os::unix::{
        io::{AsRawFd, RawFd},
        net::{UnixListener, UnixStream},
    },
    thread,
};

#[cfg(all(unix, feature = "std"))]
use uds::{UnixListenerExt, UnixSocketAddr, UnixStreamExt};

/// The default server name for our abstract shmem server
#[cfg(all(unix, not(any(target_os = "ios", target_os = "macos"))))]
const UNIX_SERVER_NAME: &str = "@libafl_unix_shmem_server";
/// `MacOS` server name is on disk, since `MacOS` doesn't support abtract domain sockets.
#[cfg(any(target_os = "ios", target_os = "macos"))]
const UNIX_SERVER_NAME: &str = "./libafl_unix_shmem_server";

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
        ShMemId::from_string(&format!("{}:{}", self.server_fd, client_id.to_string()))
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn map(&self) -> &[u8] {
        self.inner.map()
    }

    fn map_mut(&mut self) -> &mut [u8] {
        self.inner.map_mut()
    }
}

impl<SP> ServedShMemProvider<SP>
where
    SP: ShMemProvider,
{
    /// Send a request to the server, and wait for a response
    #[allow(clippy::similar_names)] // id and fd
    fn send_receive(&mut self, request: ServedShMemRequest) -> Result<(i32, i32), Error> {
        let body = postcard::to_allocvec(&request)?;

        let header = (body.len() as u32).to_be_bytes();
        let mut message = header.to_vec();
        message.extend(body);

        self.stream
            .write_all(&message)
            .expect("Failed to send message");

        let mut shm_slice = [0u8; 20];
        let mut fd_buf = [-1; 1];
        self.stream
            .recv_fds(&mut shm_slice, &mut fd_buf)
            .expect("Did not receive a response");

        let server_id = ShMemId::from_slice(&shm_slice);
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
    type Mem = ServedShMem<SP::Mem>;

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
        let (id, _) = res.send_receive(ServedShMemRequest::Hello(None))?;
        res.id = id;
        Ok(res)
    }
    fn new_map(&mut self, map_size: usize) -> Result<Self::Mem, crate::Error> {
        let (server_fd, client_fd) = self.send_receive(ServedShMemRequest::NewMap(map_size))?;

        Ok(ServedShMem {
            inner: ManuallyDrop::new(
                self.inner
                    .from_id_and_size(ShMemId::from_string(&format!("{}", client_fd)), map_size)?,
            ),
            server_fd,
        })
    }

    fn from_id_and_size(&mut self, id: ShMemId, size: usize) -> Result<Self::Mem, Error> {
        let parts = id.as_str().split(':').collect::<Vec<&str>>();
        let server_id_str = parts.get(0).unwrap();
        let (server_fd, client_fd) = self.send_receive(ServedShMemRequest::ExistingMap(
            ShMemDescription::from_string_and_size(server_id_str, size),
        ))?;
        Ok(ServedShMem {
            inner: ManuallyDrop::new(
                self.inner
                    .from_id_and_size(ShMemId::from_string(&format!("{}", client_fd)), size)?,
            ),
            server_fd,
        })
    }

    fn post_fork(&mut self, is_child: bool) -> Result<(), Error> {
        if is_child {
            // After fork, only the parent keeps the join handle.
            if let ShMemService::Started { bg_thread, .. } = &mut self.service {
                bg_thread.borrow_mut().lock().unwrap().join_handle = None;
            }
            // After fork, the child needs to reconnect as to not share the fds with the parent.
            self.stream =
                UnixStream::connect_to_unix_addr(&UnixSocketAddr::new(UNIX_SERVER_NAME)?)?;
            let (id, _) = self.send_receive(ServedShMemRequest::Hello(Some(self.id)))?;
            self.id = id;
        }
        Ok(())
    }

    fn release_map(&mut self, map: &mut Self::Mem) {
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
    Hello(Option<i32>),
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
    Mapping(Rc<RefCell<SP::Mem>>),
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
    Started {
        bg_thread: Arc<Mutex<ShMemServiceThread>>,
        phantom: PhantomData<SP>,
    },
    Failed {
        err_msg: String,
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
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            fs::remove_file(&UNIX_SERVER_NAME).unwrap();
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

                    println!("Error creating ShMemService: {:?}", e);
                    return Err(e);
                }
            };
            if let Err(e) = worker.listen(UNIX_SERVER_NAME, &childsyncpair) {
                println!("Error spawning ShMemService: {:?}", e);
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

        match *success {
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
                    err_msg: format!("{}", err),
                    phantom: PhantomData,
                }
            }
        }
    }
}

/// The struct for the worker, handling incoming requests for [`ShMem`].
struct ServedShMemServiceWorker<SP>
where
    SP: ShMemProvider,
{
    provider: SP,
    clients: HashMap<RawFd, SharedShMemClient<SP::Mem>>,
    all_maps: HashMap<i32, Weak<RefCell<SP::Mem>>>,
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
            all_maps: HashMap::new(),
        })
    }

    /// Read and handle the client request, send the answer over unix fd.
    fn handle_request(&mut self, client_id: RawFd) -> Result<ServedShMemResponse<SP>, Error> {
        let request = self.read_request(client_id)?;

        //println!("got ashmem client: {}, request:{:?}", client_id, request);
        // Handle the client request
        let response = match request {
            ServedShMemRequest::Hello(other_id) => {
                if let Some(other_id) = other_id {
                    if other_id != client_id {
                        // remove temporarily
                        let other_client = self.clients.remove(&other_id);
                        let client = self.clients.get_mut(&client_id).unwrap();
                        for (id, map) in other_client.as_ref().unwrap().maps.iter() {
                            client.maps.insert(*id, map.clone());
                        }
                        self.clients.insert(other_id, other_client.unwrap());
                    }
                };
                Ok(ServedShMemResponse::Id(client_id))
            }
            ServedShMemRequest::NewMap(map_size) => {
                let new_map = self.provider.new_map(map_size)?;
                let description = new_map.description();
                let new_rc = Rc::new(RefCell::new(new_map));
                self.all_maps
                    .insert(description.id.into(), Rc::downgrade(&new_rc));
                Ok(ServedShMemResponse::Mapping(new_rc))
            }
            ServedShMemRequest::ExistingMap(description) => {
                let client = self.clients.get_mut(&client_id).unwrap();
                let description_id: i32 = description.id.into();
                if client.maps.contains_key(&description_id) {
                    Ok(ServedShMemResponse::Mapping(
                        client
                            .maps
                            .get_mut(&description_id)
                            .as_mut()
                            .unwrap()
                            .first()
                            .as_mut()
                            .unwrap()
                            .clone(),
                    ))
                } else {
                    Ok(ServedShMemResponse::Mapping(
                        self.all_maps
                            .get_mut(&description_id)
                            .unwrap()
                            .clone()
                            .upgrade()
                            .unwrap(),
                    ))
                }
            }
            ServedShMemRequest::Deregister(map_id) => {
                let client = self.clients.get_mut(&client_id).unwrap();
                let maps = client.maps.entry(map_id).or_default();
                if maps.is_empty() {
                    Ok(ServedShMemResponse::RefCount(0u32))
                } else {
                    Ok(ServedShMemResponse::RefCount(
                        Rc::strong_count(&maps.pop().unwrap()) as u32,
                    ))
                }
            }
            ServedShMemRequest::Exit => {
                println!("ShMemService - Exiting");
                // stopping the server
                return Err(Error::ShuttingDown);
            }
        };
        //println!("send ashmem client: {}, response: {:?}", client_id, &response);

        response
    }

    fn read_request(&mut self, client_id: RawFd) -> Result<ServedShMemRequest, Error> {
        let client = self.clients.get_mut(&client_id).unwrap();

        // Always receive one be u32 of size, then the command.
        let mut size_bytes = [0u8; 4];
        client.stream.read_exact(&mut size_bytes)?;
        let size = u32::from_be_bytes(size_bytes);
        let mut bytes = vec![];
        bytes.resize(size as usize, 0u8);
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

                return Err(Error::Unknown(format!(
                    "The ShMem server appears to already be running. We are probably a client. Error: {:?}", err)));
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
                    println!("Error polling for activity: {:?}", e);
                    continue;
                }
            };
            let copied_poll_fds: Vec<PollFd> = poll_fds.iter().copied().collect();
            for poll_fd in copied_poll_fds {
                let revents = poll_fd.revents().expect("revents should not be None");
                let raw_polled_fd =
                    unsafe { *((&poll_fd as *const PollFd) as *const libc::pollfd) }.fd;
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
                                println!("Error accepting client: {:?}", e);
                                continue;
                            }
                        };

                        // println!("Recieved connection from {:?}", addr);
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
