/*!
On Android, we can only share maps between processes by serializing fds over sockets.
Hence, the `ashmem_server` keeps track of existing maps, creates new maps for clients,
and forwards them over unix domain sockets.
*/

use crate::{
    bolts::shmem::{
        unix_shmem::ashmem::{AshmemShMem, AshmemShMemProvider},
        ShMem, ShMemDescription, ShMemId, ShMemProvider,
    },
    Error,
};
use core::mem::ManuallyDrop;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    io::{Read, Write},
    rc::Rc,
    sync::{Arc, Condvar, Mutex},
};

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

const ASHMEM_SERVER_NAME: &str = "@ashmem_server";

/// Hands out served shared maps, as used on Android.
#[derive(Debug)]
pub struct ServedShMemProvider {
    stream: UnixStream,
    inner: AshmemShMemProvider,
    id: i32,
}

/// [`ShMem`] that got served from a [`AshmemService`] via domain sockets and can now be used in this program.
/// It works around Android's lack of "proper" shared maps.
#[derive(Clone, Debug)]
pub struct ServedShMem {
    inner: ManuallyDrop<AshmemShMem>,
    server_fd: i32,
}

impl ShMem for ServedShMem {
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

impl ServedShMemProvider {
    /// Send a request to the server, and wait for a response
    #[allow(clippy::similar_names)] // id and fd
    fn send_receive(&mut self, request: AshmemRequest) -> (i32, i32) {
        let body = postcard::to_allocvec(&request).unwrap();

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
        let server_id_str = server_id.to_string();
        let server_fd: i32 = server_id_str.parse().unwrap();
        (server_fd, fd_buf[0])
    }
}

impl Default for ServedShMemProvider {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

impl Clone for ServedShMemProvider {
    fn clone(&self) -> Self {
        Self::new().unwrap()
    }
}

impl ShMemProvider for ServedShMemProvider {
    type Mem = ServedShMem;

    /// Connect to the server and return a new ServedShMemProvider
    fn new() -> Result<Self, Error> {
        let mut res = Self {
            stream: UnixStream::connect_to_unix_addr(
                &UnixSocketAddr::new(ASHMEM_SERVER_NAME).unwrap(),
            )?,
            inner: AshmemShMemProvider::new()?,
            id: -1,
        };
        let (id, _) = res.send_receive(AshmemRequest::Hello(None));
        res.id = id;
        Ok(res)
    }
    fn new_map(&mut self, map_size: usize) -> Result<Self::Mem, crate::Error> {
        let (server_fd, client_fd) = self.send_receive(AshmemRequest::NewMap(map_size));

        Ok(ServedShMem {
            inner: ManuallyDrop::new(
                self.inner
                    .from_id_and_size(ShMemId::from_string(&format!("{}", client_fd)), map_size)?,
            ),
            server_fd,
        })
    }

    fn from_id_and_size(&mut self, id: ShMemId, size: usize) -> Result<Self::Mem, Error> {
        let parts = id.to_string().split(':').collect::<Vec<&str>>();
        let server_id_str = parts.get(0).unwrap();
        let (server_fd, client_fd) = self.send_receive(AshmemRequest::ExistingMap(
            ShMemDescription::from_string_and_size(server_id_str, size),
        ));
        Ok(ServedShMem {
            inner: ManuallyDrop::new(
                self.inner
                    .from_id_and_size(ShMemId::from_string(&format!("{}", client_fd)), size)?,
            ),
            server_fd,
        })
    }

    fn post_fork(&mut self) {
        self.stream =
            UnixStream::connect_to_unix_addr(&UnixSocketAddr::new(ASHMEM_SERVER_NAME).unwrap())
                .expect("Unable to reconnect to the ashmem service");
        let (id, _) = self.send_receive(AshmemRequest::Hello(Some(self.id)));
        self.id = id;
    }

    fn release_map(&mut self, map: &mut Self::Mem) {
        let (refcount, _) = self.send_receive(AshmemRequest::Deregister(map.server_fd));
        if refcount == 0 {
            unsafe {
                ManuallyDrop::drop(&mut map.inner);
            }
        }
    }
}

/// A request sent to the ShMem server to receive a fd to a shared map
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum AshmemRequest {
    /// Register a new map with a given size.
    NewMap(usize),
    /// Another client already has a map with this description mapped.
    ExistingMap(ShMemDescription),
    /// A client tells us it unregisters the previously allocated map
    Deregister(i32),
    /// A message that tells us hello, and optionally which other client we were created from, we
    /// return a client id.
    Hello(Option<i32>),
}

#[derive(Debug)]
struct AshmemClient {
    stream: UnixStream,
    maps: HashMap<i32, Vec<Rc<RefCell<AshmemShMem>>>>,
}

impl AshmemClient {
    fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            maps: HashMap::new(),
        }
    }
}

/// The AshmemService is a service handing out [`ShMem`] pages via unix domain sockets.
/// It is mainly used and needed on Android.
#[derive(Debug)]
pub struct AshmemService {
    provider: AshmemShMemProvider,
    clients: HashMap<RawFd, AshmemClient>,
    all_maps: HashMap<i32, Rc<RefCell<AshmemShMem>>>,
}

#[derive(Debug)]
enum AshmemResponse {
    Mapping(Rc<RefCell<AshmemShMem>>),
    Id(i32),
    RefCount(u32),
}

impl AshmemService {
    /// Create a new AshMem service
    fn new() -> Result<Self, Error> {
        Ok(AshmemService {
            provider: AshmemShMemProvider::new()?,
            clients: HashMap::new(),
            all_maps: HashMap::new(),
        })
    }

    /// Read and handle the client request, send the answer over unix fd.
    fn handle_request(&mut self, client_id: RawFd) -> Result<AshmemResponse, Error> {
        let request = self.read_request(client_id)?;

        //println!("got ashmem client: {}, request:{:?}", client_id, request);
        // Handle the client request
        let response = match request {
            AshmemRequest::Hello(other_id) => {
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
                Ok(AshmemResponse::Id(client_id))
            }
            AshmemRequest::NewMap(map_size) => Ok(AshmemResponse::Mapping(Rc::new(RefCell::new(
                self.provider.new_map(map_size)?,
            )))),
            AshmemRequest::ExistingMap(description) => {
                let client = self.clients.get_mut(&client_id).unwrap();
                if client.maps.contains_key(&description.id.to_int()) {
                    Ok(AshmemResponse::Mapping(
                        client
                            .maps
                            .get_mut(&description.id.to_int())
                            .as_mut()
                            .unwrap()
                            .first()
                            .as_mut()
                            .unwrap()
                            .clone(),
                    ))
                } else if self.all_maps.contains_key(&description.id.to_int()) {
                    Ok(AshmemResponse::Mapping(
                        self.all_maps
                            .get_mut(&description.id.to_int())
                            .unwrap()
                            .clone(),
                    ))
                } else {
                    let new_rc =
                        Rc::new(RefCell::new(self.provider.from_description(description)?));
                    self.all_maps
                        .insert(description.id.to_int(), new_rc.clone());
                    Ok(AshmemResponse::Mapping(new_rc))
                }
            }
            AshmemRequest::Deregister(map_id) => {
                let client = self.clients.get_mut(&client_id).unwrap();
                let map = client.maps.entry(map_id).or_default().pop().unwrap();
                Ok(AshmemResponse::RefCount(Rc::strong_count(&map) as u32))
            }
        };
        //println!("send ashmem client: {}, response: {:?}", client_id, &response);

        response
    }

    fn read_request(&mut self, client_id: RawFd) -> Result<AshmemRequest, Error> {
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
        let request: AshmemRequest = postcard::from_bytes(&bytes)?;

        Ok(request)
    }
    fn handle_client(&mut self, client_id: RawFd) -> Result<(), Error> {
        let response = self.handle_request(client_id)?;

        match response {
            AshmemResponse::Mapping(mapping) => {
                let id = mapping.borrow().id();
                let server_fd: i32 = id.to_string().parse().unwrap();
                let client = self.clients.get_mut(&client_id).unwrap();
                client
                    .stream
                    .send_fds(&id.to_string().as_bytes(), &[server_fd])?;
                client.maps.entry(server_fd).or_default().push(mapping);
            }
            AshmemResponse::Id(id) => {
                let client = self.clients.get_mut(&client_id).unwrap();
                client.stream.send_fds(&id.to_string().as_bytes(), &[])?;
            }
            AshmemResponse::RefCount(refcount) => {
                let client = self.clients.get_mut(&client_id).unwrap();
                client
                    .stream
                    .send_fds(&refcount.to_string().as_bytes(), &[])?;
            }
        }
        Ok(())
    }

    /// Create a new AshmemService, then listen and service incoming connections in a new thread.
    pub fn start() -> Result<thread::JoinHandle<Result<(), Error>>, Error> {
        #[allow(clippy::mutex_atomic)]
        let syncpair = Arc::new((Mutex::new(false), Condvar::new()));
        let childsyncpair = Arc::clone(&syncpair);
        let join_handle =
            thread::spawn(move || Self::new()?.listen(ASHMEM_SERVER_NAME, &childsyncpair));

        let (lock, cvar) = &*syncpair;
        let mut started = lock.lock().unwrap();
        while !*started {
            started = cvar.wait(started).unwrap();
        }

        Ok(join_handle)
    }

    /// Listen on a filename (or abstract name) for new connections and serve them. This function
    /// should not return.
    fn listen(
        &mut self,
        filename: &str,
        syncpair: &Arc<(Mutex<bool>, Condvar)>,
    ) -> Result<(), Error> {
        let listener = if let Ok(listener) =
            UnixListener::bind_unix_addr(&UnixSocketAddr::new(filename)?)
        {
            listener
        } else {
            let (lock, cvar) = &**syncpair;
            *lock.lock().unwrap() = true;
            cvar.notify_one();
            return Err(Error::Unknown(
                "The server appears to already be running. We are probably a client".to_string(),
            ));
        };
        let mut poll_fds: Vec<PollFd> = vec![PollFd::new(
            listener.as_raw_fd(),
            PollFlags::POLLIN | PollFlags::POLLRDNORM | PollFlags::POLLRDBAND,
        )];

        let (lock, cvar) = &**syncpair;
        *lock.lock().unwrap() = true;
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
                        let (stream, addr) = match listener.accept_unix_addr() {
                            Ok(stream_val) => stream_val,
                            Err(e) => {
                                println!("Error accepting client: {:?}", e);
                                continue;
                            }
                        };

                        println!("Recieved connection from {:?}", addr);
                        let pollfd = PollFd::new(
                            stream.as_raw_fd(),
                            PollFlags::POLLIN | PollFlags::POLLRDNORM | PollFlags::POLLRDBAND,
                        );
                        poll_fds.push(pollfd);
                        let client = AshmemClient::new(stream);
                        let client_id = client.stream.as_raw_fd();
                        self.clients.insert(client_id, client);
                        match self.handle_client(client_id) {
                            Ok(()) => (),
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
