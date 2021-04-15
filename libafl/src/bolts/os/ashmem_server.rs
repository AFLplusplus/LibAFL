/*!
On Android, we can only share maps between processes by serializing fds over sockets.
Hence, the `ashmem_server` keeps track of existing maps, creates new maps for clients,
and forwards them over unix domain sockets.
*/

use crate::{
    bolts::shmem::{
        ShMemDescription, ShMemId, ShMemMapping,
        ShMemProvider, UnixShMemMapping, UnixShMemProvider,
    },
    Error,
};
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    sync::{Arc, Condvar, Mutex},
};

#[cfg(all(feature = "std", unix))]
use nix::poll::{poll, PollFd, PollFlags};

#[cfg(all(feature = "std", unix))]
use std::{
    os::unix::{
        io::{RawFd, AsRawFd},
        net::{UnixListener, UnixStream},
    },
    thread,
};

#[cfg(all(unix, feature = "std"))]
use uds::{UnixListenerExt, UnixSocketAddr, UnixStreamExt};

const ASHMEM_SERVER_NAME: &str = "@ashmem_server";

#[derive(Debug)]
pub struct ServedShMemProvider {
    stream: UnixStream,
    inner: UnixShMemProvider,
}

#[derive(Clone, Debug)]
pub struct ServedShMemMapping {
    inner: UnixShMemMapping,
    server_fd: i32,
}

impl ShMemMapping for ServedShMemMapping {
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
    /// Connect to the server and return a new ServedShMemProvider
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            stream: UnixStream::connect_to_unix_addr(
                &UnixSocketAddr::new(ASHMEM_SERVER_NAME).unwrap(),
            )?,
            inner: UnixShMemProvider::new(),
        })
    }

    /// Send a request to the server, and wait for a response
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

impl ShMemProvider for ServedShMemProvider {
    type Mapping = ServedShMemMapping;
    fn new_map(&mut self, map_size: usize) -> Result<Self::Mapping, crate::Error> {
        let (server_fd, client_fd) = self.send_receive(AshmemRequest::NewMap(map_size));

        Ok(ServedShMemMapping {
            inner: self
                .inner
                .from_id_and_size(ShMemId::from_string(&format!("{}", client_fd)), map_size)?,
            server_fd,
        })
    }

    fn from_id_and_size(&mut self, id: ShMemId, size: usize) -> Result<Self::Mapping, Error> {
        let parts = id.to_string().split(':').collect::<Vec<&str>>();
        let server_id_str = parts.get(0).unwrap();
        let (server_fd, client_fd) =  self.send_receive(AshmemRequest::ExistingMap(
            ShMemDescription::from_string_and_size(server_id_str, size),
        ));
        Ok(ServedShMemMapping {
            inner: self
                .inner
                .from_id_and_size(ShMemId::from_string(&format!("{}", client_fd)), size)?,
            server_fd,
        })
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
    Deregister(u32),
}

#[derive(Debug)]
struct AshmemClient {
    stream: UnixStream,
}

impl AshmemClient {
    fn new(stream: UnixStream) -> Self {
        Self { stream }
    }
}

#[derive(Debug)]
pub struct AshmemService {
    provider: UnixShMemProvider,
    maps: Vec<UnixShMemMapping>,
}

impl AshmemService {
    /// Create a new AshMem service
    #[must_use]
    fn new() -> Self {
        AshmemService {
            provider: UnixShMemProvider::new(),
            maps: Vec::new(),
        }
    }

    /// Read and handle the client request, send the answer over unix fd.
    fn handle_client(&mut self, client: &mut AshmemClient) -> Result<(), Error> {
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

        // Handle the client request
        let mapping = match request {
            AshmemRequest::NewMap(map_size) => self.provider.new_map(map_size)?,
            AshmemRequest::ExistingMap(description) => {
                self.provider.from_description(description)?
            }
            AshmemRequest::Deregister(_) => {
                return Ok(());
            }
        };

        let id = mapping.id();
        let server_fd: i32 = id.to_string().parse().unwrap();
        client
            .stream
            .send_fds(&id.to_string().as_bytes(), &[server_fd])?;
        self.maps.push(mapping);
        Ok(())
    }

    /// Create a new AshmemService, then listen and service incoming connections in a new thread.
    pub fn start() -> Result<thread::JoinHandle<Result<(), Error>>, Error> {
        #[allow(clippy::mutex_atomic)]
        let syncpair = Arc::new((Mutex::new(false), Condvar::new()));
        let childsyncpair = Arc::clone(&syncpair);
        let join_handle =
            thread::spawn(move || Self::new().listen(ASHMEM_SERVER_NAME, childsyncpair));

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
        syncpair: Arc<(Mutex<bool>, Condvar)>,
    ) -> Result<(), Error> {
        let listener = if let Ok(listener) =
            UnixListener::bind_unix_addr(&UnixSocketAddr::new(filename)?)
        {
            listener
        } else {
            let (lock, cvar) = &*syncpair;
            *lock.lock().unwrap() = true;
            cvar.notify_one();
            return Err(Error::Unknown(
                "The server appears to already be running. We are probably a client".to_string(),
            ));
        };
        let mut clients: HashMap<RawFd, AshmemClient> = HashMap::new();
        let mut poll_fds: Vec<PollFd> = vec![PollFd::new(
            listener.as_raw_fd(),
            PollFlags::POLLIN | PollFlags::POLLRDNORM | PollFlags::POLLRDBAND,
        )];

        let (lock, cvar) = &*syncpair;
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
                    clients.remove(&raw_polled_fd);
                } else if revents.contains(PollFlags::POLLIN) {
                    if clients.contains_key(&raw_polled_fd) {
                        let mut client = clients.get_mut(&raw_polled_fd).unwrap();
                        match self.handle_client(&mut client) {
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
                        let mut client = AshmemClient::new(stream);
                        match self.handle_client(&mut client) {
                            Ok(()) => (),
                            Err(e) => {
                                dbg!("Ignoring failed read from client", e);
                            }
                        };
                        clients.insert(client.stream.as_raw_fd(), client);
                    }
                } else {
                    //println!("Unknown revents flags: {:?}", revents);
                }
            }
        }
    }
}
