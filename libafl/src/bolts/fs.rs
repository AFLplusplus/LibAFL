//! `LibAFL` functionality for filesystem interaction

use std::{
    fs::{self, remove_file, File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::prelude::{AsRawFd, RawFd};

use crate::Error;

/// The default filename to use to deliver testcases to the target
pub const OUTFILE_STD: &str = ".cur_input";

/// Creates a `.{file_name}.tmp` file, and writes all bytes to it.
/// After all bytes have been written, the tmp-file is moved to it's original `path`.
/// This way, on the majority of operating systems, the final file will never be incomplete or racey.
/// It will overwrite existing files with the same filename.
///
/// # Errors
/// Can error if the file doesn't exist, or if the `.{file-name}.tmp` file already exists.
pub fn write_file_atomic<P>(path: P, bytes: &[u8]) -> Result<(), Error>
where
    P: AsRef<Path>,
{
    fn inner(path: &Path, bytes: &[u8]) -> Result<(), Error> {
        let mut tmpfile_name = path.to_path_buf();
        tmpfile_name.set_file_name(format!(
            ".{}.tmp",
            tmpfile_name.file_name().unwrap().to_string_lossy()
        ));

        let mut tmpfile = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmpfile_name)?;

        tmpfile.write_all(bytes)?;
        fs::rename(&tmpfile_name, path)?;
        Ok(())
    }
    inner(path.as_ref(), bytes)
}

/// An [`OutFile`] to write fuzzer input to.
/// The target/forkserver will read from this file.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct OutFile {
    /// The filename/path too this [`OutFile`]
    pub path: PathBuf,
    /// The underlying file that got created
    pub file: File,
}

impl Eq for OutFile {}

impl PartialEq for OutFile {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl Clone for OutFile {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            file: self.file.try_clone().unwrap(),
        }
    }
}

#[cfg(feature = "std")]
impl OutFile {
    /// Creates a new [`OutFile`]
    pub fn create<P>(filename: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&filename)?;
        f.set_len(0)?;
        Ok(Self {
            path: filename.as_ref().to_owned(),
            file: f,
        })
    }

    /// Gets the file as raw file descriptor
    #[must_use]
    #[cfg(unix)]
    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    /// Writes the given buffer to the file
    pub fn write_buf(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.rewind()?;
        self.file.write_all(buf)?;
        self.file.set_len(buf.len() as u64)?;
        self.file.flush()?;
        // Rewind again otherwise the target will not read stdin from the beginning
        self.rewind()
    }

    /// Rewinds the file to the beginning
    #[inline]
    pub fn rewind(&mut self) -> Result<(), Error> {
        if let Err(err) = self.file.seek(SeekFrom::Start(0)) {
            Err(err.into())
        } else {
            Ok(())
        }
    }
}

#[cfg(feature = "std")]
impl Drop for OutFile {
    fn drop(&mut self) {
        // try to remove the file, but ignore errors
        drop(remove_file(&self.path));
    }
}

#[cfg(test)]
mod test {
    use crate::bolts::fs::write_file_atomic;
    use std::fs;

    #[test]
    fn test_atomic_file_write() {
        let path = "atomic_file_testfile";

        write_file_atomic(&path, b"test").unwrap();
        let content = fs::read_to_string(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(content, "test");
    }
}
