use alloc::string::String;
use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

use crate::{
    GuestAddr,
    mmap::{Mmap, MmapProt},
};

pub struct MapEntry {
    base: GuestAddr,
    limit: GuestAddr,
    read: bool,
    write: bool,
    exec: bool,
    private: bool,
    offset: u64,
    major: u32,
    minor: u32,
    inode: usize,
    path: String,
}

impl Debug for MapEntry {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        write!(
            fmt,
            "{:016x}-{:016x} {}{}{}{} {:08x} {:02x}:{:02x} {:10} {}",
            self.base,
            self.limit,
            if self.read { 'r' } else { '-' },
            if self.write { 'w' } else { '-' },
            if self.exec { 'x' } else { '-' },
            match self.private {
                true => 'p',
                false => 's',
            },
            self.offset,
            self.major,
            self.minor,
            self.inode,
            self.path,
        )?;
        Ok(())
    }
}

impl MapEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base: GuestAddr,
        limit: GuestAddr,
        read: bool,
        write: bool,
        exec: bool,
        private: bool,
        offset: u64,
        major: u32,
        minor: u32,
        inode: usize,
        path: String,
    ) -> Self {
        Self {
            base,
            limit,
            read,
            write,
            exec,
            private,
            offset,
            major,
            minor,
            inode,
            path,
        }
    }

    pub fn contains(&self, addr: GuestAddr) -> bool {
        addr >= self.base && addr < self.limit
    }

    fn base(&self) -> GuestAddr {
        self.base
    }

    fn len(&self) -> usize {
        self.limit - self.base
    }

    pub fn prot(&self) -> MmapProt {
        let mut prot = MmapProt::empty();
        if self.read {
            prot |= MmapProt::READ;
        }
        if self.write {
            prot |= MmapProt::WRITE;
        }
        if self.exec {
            prot |= MmapProt::EXEC;
        }
        prot
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn writeable<M: Mmap>(&self) -> Result<WriteableMapProtection<'_, M>, M::Error> {
        if !self.write {
            M::protect(self.base(), self.len(), self.prot() | MmapProt::WRITE)?;
        }
        Ok(WriteableMapProtection {
            map_entry: self,
            phantom: PhantomData,
        })
    }
}

pub struct WriteableMapProtection<'a, M: Mmap> {
    map_entry: &'a MapEntry,
    phantom: PhantomData<M>,
}

impl<M: Mmap> Drop for WriteableMapProtection<'_, M> {
    fn drop(&mut self) {
        if !self.map_entry.write {
            M::protect(
                self.map_entry.base(),
                self.map_entry.len(),
                self.map_entry.prot(),
            )
            .unwrap();
        }
    }
}
