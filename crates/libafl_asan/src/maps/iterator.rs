use alloc::string::String;
use core::fmt::Debug;

use crate::{
    GuestAddr,
    file::FileReader,
    maps::{decode::MapDecode, entry::MapEntry},
};

const BUFFER_SIZE: usize = 4096;

#[derive(Debug)]
enum MapState {
    Base,
    Limit,
    Properties,
    Offset,
    Major,
    Minor,
    Inode,
    Path,
}

#[derive(Debug)]
pub struct MapIterator<R: FileReader> {
    source: R,
    buffer: [u8; BUFFER_SIZE],
    buff_len: usize,
    state: MapState,
}

impl<R: FileReader> MapIterator<R> {
    pub fn new() -> Result<MapIterator<R>, R::Error> {
        let source = R::new(c"/proc/self/maps")?;
        Ok(MapIterator {
            source,
            buffer: [0; BUFFER_SIZE],
            buff_len: 0,
            state: MapState::Base,
        })
    }
}

impl<R: FileReader> Iterator for MapIterator<R> {
    type Item = MapEntry;

    fn next(&mut self) -> Option<MapEntry> {
        let mut base: GuestAddr = 0;
        let mut limit: GuestAddr = 0;
        let mut read: bool = false;
        let mut write: bool = false;
        let mut exec: bool = false;
        let mut private: bool = false;
        let mut offset: u64 = 0;
        let mut major: u32 = 0;
        let mut minor: u32 = 0;
        let mut inode: usize = 0;
        let mut path: String = String::new();
        loop {
            let slice = &mut self.buffer[self.buff_len..];

            self.buff_len += self.source.read(slice).ok()?;
            if self.buff_len == 0 {
                break;
            }

            for i in 0..self.buff_len {
                let c = self.buffer[i];
                match self.state {
                    MapState::Base => match c {
                        b'-' => self.state = MapState::Limit,
                        _ => {
                            base *= 16;
                            base += GuestAddr::from_hex(c).ok()?;
                        }
                    },
                    MapState::Limit => match c {
                        b' ' => self.state = MapState::Properties,
                        _ => {
                            limit *= 16;
                            limit += GuestAddr::from_hex(c).ok()?;
                        }
                    },
                    MapState::Properties => match c {
                        b' ' => self.state = MapState::Offset,
                        b'-' => (),
                        b'r' => read = true,
                        b'w' => write = true,
                        b'x' => exec = true,
                        b'p' => private = true,
                        b's' => private = false,
                        _ => return None,
                    },
                    MapState::Offset => match c {
                        b' ' => self.state = MapState::Major,
                        _ => {
                            offset *= 16;
                            offset += u64::from_hex(c).ok()?;
                        }
                    },
                    MapState::Major => match c {
                        b':' => self.state = MapState::Minor,
                        _ => {
                            major *= 16;
                            major += u32::from_hex(c).ok()?;
                        }
                    },
                    MapState::Minor => match c {
                        b' ' => self.state = MapState::Inode,
                        _ => {
                            minor *= 16;
                            minor += u32::from_hex(c).ok()?;
                        }
                    },
                    MapState::Inode => match c {
                        b' ' => self.state = MapState::Path,
                        _ => {
                            inode *= 10;
                            inode += usize::from_dec(c).ok()?;
                        }
                    },
                    MapState::Path => match c {
                        b' ' => {
                            if !path.is_empty() {
                                path.push(' ');
                            }
                        }
                        b'\n' => {
                            self.state = MapState::Base;
                            self.buff_len -= i + 1;
                            self.buffer.copy_within(i + 1.., 0);
                            let entry = MapEntry::new(
                                base, limit, read, write, exec, private, offset, major, minor,
                                inode, path,
                            );
                            return Some(entry);
                        }
                        _ => {
                            path.push(c as char);
                        }
                    },
                }
            }
        }
        None
    }
}
