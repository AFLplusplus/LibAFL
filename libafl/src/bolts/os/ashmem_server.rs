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

#[cfg(all(feature = "std", unix))]
use nix::{
    cmsg_space,
    sys::{
        socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags},
        uio::IoVec,
    },
};

#[cfg(all(feature = "std", unix))]
use std::os::unix::{
    self,
    net::{UnixListener, UnixStream},
    {io::AsRawFd, prelude::RawFd},
};

#[cfg(all(unix, feature = "std"))]
use uds::{UnixListenerExt, UnixSocketAddr, UnixStreamExt};

/// The implementing channel has the ability to send a file descriptor.
pub trait SendFd {
    /// Sends a file descriptor
    fn send_fd(&self, fd: i32) -> Result<(), Error>;
}

/// Send a file descriptor over a unix stream
impl SendFd for UnixStream {
    fn send_fd(&self, fd: i32) -> Result<(), Error> {
        match sendmsg(
            self.as_raw_fd(),
            &[IoVec::from_slice(b"\x00")],
            &[ControlMessage::ScmRights(&[fd])],
            MsgFlags::empty(),
            None,
        ) {
            // TODO: Return a more appropriate Error
            Err(e) => Err(Error::Unknown(format!(
                "Could not send fd to Unix Socket {} {:?}: {:?}",
                fd, self, e
            ))),
            Ok(_) => Ok(()),
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
/// The Sharedmem backed by a `ShmemService`a
pub struct ServedShMem {}

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
    maps: Vec<UnixShMem>,
}

pub impl AshmemService {
    /// Create a new AshMem service
    #[must_use]
    pub fn new() -> Self {
        AshmemService { maps: vec![] }
    }

    /// Read and handle the client request, send the answer over unix fd.
    fn handle_client(&mut self, stream: UnixStream) -> Result<(), Error> {
        // Always receive one be u32 of size, then the command.
        let mut size_bytes = [0u8; 4];
        stream.read_exact(&mut size_bytes)?;
        let size = u32::from_be_bytes(size_bytes);
        let bytes = vec![];
        bytes.resize(size as usize, 0u8);
        stream.read_exact(&mut bytes);
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

                    self.maps.push(map);
                    fd
                }
            },
            AshmemRequest::ExistingPage(description) => {
                let map = None;
                for shmem in self.maps {
                    if shmem.shm_str() == description.str_bytes {
                        map = Some(shmem);
                    }
                }

                match map {
                    None => {
                        println!("Error finding shared map {:?}", description);
                        -1
                    }
                    Some(map) => map.shm_id,
                }
            }
            AshmemRequest::Deregister(id) => {
                return Ok(());
            }
        };

        stream.send_fds(&fd.to_be_bytes(), &[fd])?;
        Ok(())
    }
}

pub fn listen(&self, filename: &str) -> Result<(), Error> {
    let listener = UnixListener::bind_unix_addr(&UnixSocketAddr::new(filename)?)?;

    loop {
        let (stream, addr) = match listener.accept() {
            Ok(stream_val) => stream_val,
            Err(e) => {
                println!("Error accepting client: {:?}", e);
                continue;
            }
        };

        println!("Recieved connection from {:?}", addr);

        match self.handle_client(stream) {
            Ok(()) => (),
            Err(e) => {
                dbg!("Ignoring failed read from client", e);
                continue;
            }
        };
    }
}
