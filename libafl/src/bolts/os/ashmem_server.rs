/*!
On Android, we can only share maps between processes by serializing fds over sockets.
Hence, the `ashmem_server` keeps track of existing maps, creates new maps for clients,
and forwards them over unix domain sockets.
*/

use crate::{
    bolts::shmem::{ShMem, ShMemDescription, UnixShMem},
    Error,
};
use serde::{Deserialize, Serialize};
use std::io::Read;
use hashbrown::HashMap;

#[cfg(all(feature = "std", unix))]
use nix::{
    cmsg_space,
    poll::{poll, PollFlags, PollFd},
};

#[cfg(all(feature = "std", unix))]
use std::os::unix::{
    self,
    net::{UnixListener, UnixStream},
    {io::AsRawFd, prelude::RawFd},
};

use std::rc::Rc;

#[cfg(all(unix, feature = "std"))]
use uds::{UnixListenerExt, UnixSocketAddr, UnixStreamExt};

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
/// The Sharedmem backed by a `ShmemService`a
pub struct ServedShMem {

}

impl ShMem for ServedShMem {
    fn new_map(map_size: usize) -> Result<Self, crate::Error> {
        todo!()
    }

    fn existing_from_shm_slice(
        map_str_bytes: &[u8; 20],
        map_size: usize,
    ) -> Result<Self, crate::Error> {
        todo!()
    }

    fn shm_slice(&self) -> &[u8; 20] {
        todo!()
    }

    fn map(&self) -> &[u8] {
        todo!()
    }

    fn map_mut(&mut self) -> &mut [u8] {
        todo!()
    }
}

/// A request sent to the ShMem server to receive a fd to a shared map
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum AshmemRequest {
    /// Register a new map with a given size.
    NewPage(usize),
    /// Another client already has a page with this description mapped.
    ExistingPage(ShMemDescription),
    /// A client tells us it unregistes the previously allocated map
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
            AshmemRequest::NewPage(map_size) => match UnixShMem::new(map_size) {
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
            AshmemRequest::ExistingPage(description) => {
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


    pub fn listen(&mut self, filename: &str) -> Result<(), Error> {
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

