//! `LibAFL` functionality for filesystem interaction

use alloc::rc::Rc;
#[cfg(feature = "std")]
use alloc::{borrow::ToOwned, vec::Vec};
use core::cell::RefCell;
#[cfg(feature = "std")]
use core::time::Duration;
#[cfg(unix)]
use std::os::unix::prelude::{AsRawFd, RawFd};
#[cfg(feature = "std")]
use std::time::SystemTime;
use std::{
    fs::{self, remove_file, File, OpenOptions},
    io::{Seek, Write},
    path::{Path, PathBuf},
    string::String,
};

use crate::Error;

/// The default filename to use to deliver testcases to the target
pub const INPUTFILE_STD: &str = ".cur_input";

#[must_use]
/// Derives a filename from [`INPUTFILE_STD`] that may be used to deliver testcases to the target.
/// It ensures the filename is unique to the fuzzer process.
pub fn get_unique_std_input_file() -> String {
    format!("{}_{}", INPUTFILE_STD, std::process::id())
}

/// Write a file atomically
///
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

/// An [`InputFile`] to write fuzzer input to.
/// The target/forkserver will read from this file.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct InputFile {
    /// The filename/path too this [`InputFile`]
    pub path: PathBuf,
    /// The underlying file that got created
    pub file: File,
    /// The ref count for this [`InputFile`].
    /// Once it reaches 0, the underlying [`File`] will be removed.
    pub rc: Rc<RefCell<usize>>,
}

impl Eq for InputFile {}

impl PartialEq for InputFile {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl Clone for InputFile {
    fn clone(&self) -> Self {
        {
            let mut rc = self.rc.borrow_mut();
            assert_ne!(*rc, usize::MAX, "InputFile rc overflow");
            *rc += 1;
        }
        Self {
            path: self.path.clone(),
            file: self.file.try_clone().unwrap(),
            rc: self.rc.clone(),
        }
    }
}

#[cfg(feature = "std")]
impl InputFile {
    /// Creates a new [`InputFile`], or truncates if it already exists
    pub fn create<P>(filename: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let f = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&filename)?;
        Ok(Self {
            path: filename.as_ref().to_owned(),
            file: f,
            rc: Rc::new(RefCell::new(1)),
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
        if let Err(err) = self.file.rewind() {
            Err(err.into())
        } else {
            Ok(())
        }
    }
}

/// Finds new files in the given directory, taking the last time we looked at this path as parameter.
/// This method works recursively.
/// If `last` is `None`, it'll load all file.
#[cfg(feature = "std")]
pub fn find_new_files_rec<P: AsRef<Path>>(
    dir: P,
    last_check: &Option<Duration>,
) -> Result<Vec<PathBuf>, Error> {
    let mut new_files = Vec::<PathBuf>::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let attributes = fs::metadata(&path);

        if attributes.is_err() {
            continue;
        }

        let attr = attributes?;

        if attr.is_file() && attr.len() > 0 {
            if let Ok(time) = attr.modified() {
                if let Some(last_check) = last_check {
                    if time.duration_since(SystemTime::UNIX_EPOCH).unwrap() < *last_check {
                        continue;
                    }
                }
                new_files.push(path.clone());
            }
        } else if attr.is_dir() {
            let dir_left_to_sync = find_new_files_rec(entry.path(), last_check)?;
            new_files.extend(dir_left_to_sync);
        }
    }

    Ok(new_files)
}

#[cfg(feature = "std")]
impl Drop for InputFile {
    fn drop(&mut self) {
        let mut rc = self.rc.borrow_mut();
        assert_ne!(*rc, 0, "InputFile rc should never be 0");
        *rc -= 1;
        if *rc == 0 {
            // try to remove the file, but ignore errors
            drop(remove_file(&self.path));
        }
    }
}

#[cfg(test)]
mod test {
    use std::fs;

    use crate::fs::{write_file_atomic, InputFile};

    #[test]
    fn test_atomic_file_write() {
        let path = "test_atomic_file_write.tmp";
        write_file_atomic(path, b"test").unwrap();
        let content = fs::read_to_string(path).unwrap();
        fs::remove_file(path).unwrap();
        assert_eq!(content, "test");
    }

    #[test]
    fn test_cloned_ref() {
        let mut one = InputFile::create("test_cloned_ref.tmp").unwrap();
        let two = one.clone();
        one.write_buf("Welp".as_bytes()).unwrap();
        drop(one);
        assert_eq!("Welp", fs::read_to_string(two.path.as_path()).unwrap());
    }
}
