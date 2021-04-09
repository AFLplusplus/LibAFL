/*!
On Android, we can only share maps between processes by serializing fds over sockets.
Hence, the `ashmem_server` keeps track of existing maps, creates new maps for clients,
and forwards them over unix domain sockets.
*/

use crate::{
    bolts::shmem::{ShMem, ShMemDescription, UnixShMem},
    Error,
};
use libc::c_char;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use hashbrown::HashMap;

#[cfg(all(feature = "std", unix))]
use nix::{
    cmsg_space,
    poll::{poll, PollFlags, PollFd},
};

#[cfg(all(feature = "std", unix))]
use std::{
    os::unix::{
        self,
        net::{UnixListener, UnixStream},
        {io::AsRawFd, prelude::RawFd},
    },
    thread,
};

#[cfg(all(unix, feature = "std"))]
use uds::{UnixListenerExt, UnixSocketAddr, UnixStreamExt};

#[derive(Debug)]
/// The Sharedmem backed by a `ShmemService`a
pub struct ServedShMem {
    stream: UnixStream,
    shmem: Option<UnixShMem>,
    slice: Option<[u8; 20]>,
    fd: Option<RawFd>,

}
const ASHMEM_SERVER_NAME: &str = "@ashmem_server";

impl ServedShMem {
    pub fn connect(name: &str) -> Self {
        Self {
            stream: UnixStream::connect_to_unix_addr(&UnixSocketAddr::from_abstract(name).unwrap())
                .expect("Failed to connect to the ashmem server"),
            shmem: None,
            slice: None,
            fd: None,
        }
    }

    fn send_receive(&mut self, request: AshmemRequest) -> ([u8; 20], RawFd) {
        let body  = postcard::to_allocvec(&request).unwrap();

        let header = (body.len() as u32).to_be_bytes();
        let mut message = header.to_vec();
        message.extend(body);

        self.stream.write_all(&message).expect("Failed to send message");

        let mut shm_slice = [0u8; 20];
        let mut fd_buf = [-1; 1];
        self.stream.recv_fds(&mut shm_slice, &mut fd_buf).expect("Did not receive a response");
        (shm_slice, fd_buf[0])
    }
}
impl ShMem for ServedShMem {
    fn new_map(map_size: usize) -> Result<Self, crate::Error> {
        let mut res = Self::connect(ASHMEM_SERVER_NAME);
        let (shm_slice, fd) = res.send_receive(AshmemRequest::NewMap(map_size));
        if fd == -1 {
            Err(Error::IllegalState("Could not allocate from the ashmem server".to_string()))
        } else {
            res.slice = Some(shm_slice);
            res.fd = Some(fd);
            res.shmem = Some(UnixShMem::existing_from_shm_slice(&shm_slice, map_size).expect("Failed to create the UnixShMem"));
            Ok(res)
        }
    }

    fn existing_from_shm_slice(
        map_str_bytes: &[u8; 20],
        map_size: usize,
    ) -> Result<Self, crate::Error> {
        let mut res = Self::connect(ASHMEM_SERVER_NAME);
        let (shm_slice, fd) = res.send_receive(AshmemRequest::ExistingMap(ShMemDescription {size: map_size, str_bytes: *map_str_bytes}));
        if fd == -1 {
            Err(Error::IllegalState("Could not allocate from the ashmem server".to_string()))
        } else {
            res.slice = Some(shm_slice);
            res.fd = Some(fd);
            res.shmem = Some(UnixShMem::existing_from_shm_slice(&shm_slice, map_size).expect("Failed to create the UnixShMem"));
            Ok(res)
        }
    }

    fn shm_slice(&self) -> &[u8; 20] {
        self.slice.as_ref().unwrap()
    }

    fn map(&self) -> &[u8] {
        self.shmem.as_ref().unwrap().map()
    }

    fn map_mut(&mut self) -> &mut [u8] {
        self.shmem.as_mut().unwrap().map_mut()
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
pub struct AshmemClient {
    unix_socket_file: String,
}

#[derive(Debug)]
pub struct AshmemService {
    maps: HashMap<[u8; 20], UnixShMem>,
}

impl AshmemService {
    /// Create a new AshMem service
    #[must_use]
    pub fn new() -> Self {
        AshmemService { maps: HashMap::new() }
    }

    /// Read and handle the client request, send the answer over unix fd.
    fn handle_client(&mut self, stream: &mut UnixStream) -> Result<(), Error> {
        // Always receive one be u32 of size, then the command.
        let mut size_bytes = [0u8; 4];
        stream.read_exact(&mut size_bytes)?;
        let size = u32::from_be_bytes(size_bytes);
        let mut bytes = vec![];
        bytes.resize(size as usize, 0u8);
        stream.read_exact(&mut bytes).expect("Failed to read message body");
        let request: AshmemRequest = postcard::from_bytes(&bytes)?;

        // Handle the client request
        let fd: i32 = match request {
            AshmemRequest::NewMap(map_size) => match UnixShMem::new(map_size) {
                Err(e) => {
                    println!("Error allocating shared map {:?}", e);
                    -1
                }
                Ok(map) => {
                    let fd = map.shm_id;

                    self.maps.insert(*map.shm_slice(), map);
                    fd
                }
            },
            AshmemRequest::ExistingMap(description) => {
                match self.maps.get(&description.str_bytes) {
                    None => {
                        println!("Error finding shared map {:?}", description);
                        -1
                    }
                    Some(map) => map.shm_id,
                }
            }
            AshmemRequest::Deregister(_) => {
                return Ok(());
            }
        };

        stream.send_fds(&fd.to_be_bytes(), &[fd])?;
        Ok(())
    }

    pub fn start(&'static mut self) ->  Result<thread::JoinHandle<()>, Error> {
        Ok(thread::spawn(move || {
            self.listen(ASHMEM_SERVER_NAME).unwrap()
        }))
    }

    fn listen(&mut self, filename: &str) -> Result<(), Error> {
        let listener = UnixListener::bind_unix_addr(&UnixSocketAddr::new(filename)?)?;
        let mut clients: HashMap<RawFd, (UnixStream, UnixSocketAddr)> = HashMap::new();
        let mut poll_fds: HashMap<RawFd, PollFd> = HashMap::new();

        poll_fds.insert(listener.as_raw_fd(), PollFd::new(listener.as_raw_fd(), PollFlags::POLLIN));

        loop {
            let mut fds_to_poll: Vec<PollFd> = poll_fds.values().map(|p| *p).collect();
            let fd = match poll(&mut fds_to_poll, -1) {
                Ok(fd) => fd,
                Err(e) => {
                    println!("Error polling for activity: {:?}", e);
                    continue;
                }
            };
            if fd == listener.as_raw_fd() {
                let (stream, addr) = match listener.accept_unix_addr() {
                    Ok(stream_val) => stream_val,
                    Err(e) => {
                        println!("Error accepting client: {:?}", e);
                        continue;
                    }
                };

                println!("Recieved connection from {:?}", addr);
                let pollfd = PollFd::new(stream.as_raw_fd(), PollFlags::POLLIN);
                poll_fds.insert(stream.as_raw_fd(), pollfd);
                clients.insert(stream.as_raw_fd(), (stream, addr)).as_ref().unwrap();
            } else if poll_fds.get(&fd).unwrap().revents().unwrap().contains(PollFlags::POLLHUP) {
                    poll_fds.remove(&fd);
                    clients.remove(&fd);
            } else {
                let (stream, _addr) = clients.get_mut(&fd).unwrap();
                match self.handle_client(stream) {
                    Ok(()) => (),
                    Err(e) => {
                        dbg!("Ignoring failed read from client", e);
                        continue;
                    }
                };
            }
        }
    }
}

