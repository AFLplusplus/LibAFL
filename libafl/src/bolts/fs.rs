//! LibAFL methods for filesystem interaction

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use crate::Error;

/// Creates a `.{file_name}.tmp` file, and writes all bytes to it.
/// After all bytes have been written, the tmp-file is moved to it's original `path`.
/// This way, on the majority of OSses, the final file will never be incomplete or racey.
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

        tmpfile.write_all(&bytes)?;
        fs::rename(&tmpfile_name, path)?;
        Ok(())
    }
    inner(path.as_ref(), bytes)
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
