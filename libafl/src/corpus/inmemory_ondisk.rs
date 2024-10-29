//! The [`InMemoryOnDiskCorpus`] stores [`Testcase`]s to disk.
//!
//! Additionally, _all_ of them are kept in memory.
//! For a lower memory footprint, consider using [`crate::corpus::CachedOnDiskCorpus`]
//! which only stores a certain number of [`Testcase`]s and removes additional ones in a FIFO manner.

use alloc::string::String;
use core::cell::RefCell;
#[cfg(feature = "std")]
use std::{fs, fs::File, io::Write};
use std::{
    fs::OpenOptions,
    io,
    path::{Path, PathBuf},
};

#[cfg(feature = "gzip")]
use libafl_bolts::compress::GzipCompressor;
use serde::{Deserialize, Serialize};

use super::{
    ondisk::{OnDiskMetadata, OnDiskMetadataFormat},
    HasTestcase,
};
use crate::{
    corpus::{Corpus, CorpusId, InMemoryCorpus, Testcase},
    inputs::Input,
    Error, HasMetadata,
};

/// Creates the given `path` and returns an error if it fails.
/// If the create succeeds, it will return the file.
/// If the create fails for _any_ reason, including, but not limited to, a preexisting existing file of that name,
/// it will instead return the respective [`io::Error`].
fn create_new<P: AsRef<Path>>(path: P) -> Result<File, io::Error> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

/// Tries to create the given `path` and returns `None` _only_ if the file already existed.
/// If the create succeeds, it will return the file.
/// If the create fails for some other reason, it will instead return the respective [`io::Error`].
fn try_create_new<P: AsRef<Path>>(path: P) -> Result<Option<File>, io::Error> {
    match create_new(path) {
        Ok(ret) => Ok(Some(ret)),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(None),
        Err(err) => Err(err),
    }
}

/// A corpus able to store [`Testcase`]s to disk, while also keeping all of them in memory.
///
/// Metadata is written to a `.<filename>.metadata` file in the same folder by default.
#[cfg(feature = "std")]
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct InMemoryOnDiskCorpus<I> {
    inner: InMemoryCorpus<I>,
    dir_path: PathBuf,
    meta_format: Option<OnDiskMetadataFormat>,
    prefix: Option<String>,
    locking: bool,
}

impl<I> Corpus for InMemoryOnDiskCorpus<I>
where
    I: Input,
{
    type Input = I;

    /// Returns the number of all enabled entries
    #[inline]
    fn count(&self) -> usize {
        self.inner.count()
    }

    /// Returns the number of all disabled entries
    fn count_disabled(&self) -> usize {
        self.inner.count_disabled()
    }

    /// Returns the number of elements including disabled entries
    #[inline]
    fn count_all(&self) -> usize {
        self.inner.count_all()
    }

    /// Add an enabled testcase to the corpus and return its index
    #[inline]
    fn add(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        let id = self.inner.add(testcase)?;
        let testcase = &mut self.get(id).unwrap().borrow_mut();
        self.save_testcase(testcase, id)?;
        *testcase.input_mut() = None;
        Ok(id)
    }

    /// Add a disabled testcase to the corpus and return its index
    #[inline]
    fn add_disabled(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        let id = self.inner.add_disabled(testcase)?;
        let testcase = &mut self.get_from_all(id).unwrap().borrow_mut();
        self.save_testcase(testcase, id)?;
        *testcase.input_mut() = None;
        Ok(id)
    }

    /// Replaces the testcase at the given idx
    #[inline]
    fn replace(&mut self, id: CorpusId, testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        let entry = self.inner.replace(id, testcase)?;
        self.remove_testcase(&entry)?;
        let testcase = &mut self.get(id).unwrap().borrow_mut();
        self.save_testcase(testcase, id)?;
        *testcase.input_mut() = None;
        Ok(entry)
    }

    /// Removes an entry from the corpus, returning it if it was present; considers both enabled and disabled corpus
    #[inline]
    fn remove(&mut self, id: CorpusId) -> Result<Testcase<I>, Error> {
        let entry = self.inner.remove(id)?;
        self.remove_testcase(&entry)?;
        Ok(entry)
    }

    /// Get by id; considers only enabled testcases
    #[inline]
    fn get(&self, id: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        self.inner.get(id)
    }

    /// Get by id; considers both enabled and disabled testcases
    #[inline]
    fn get_from_all(&self, id: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        self.inner.get_from_all(id)
    }

    /// Current testcase scheduled
    #[inline]
    fn current(&self) -> &Option<CorpusId> {
        self.inner.current()
    }

    /// Current testcase scheduled (mutable)
    #[inline]
    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        self.inner.current_mut()
    }

    #[inline]
    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        self.inner.next(id)
    }

    /// Peek the next free corpus id
    #[inline]
    fn peek_free_id(&self) -> CorpusId {
        self.inner.peek_free_id()
    }

    #[inline]
    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        self.inner.prev(id)
    }

    #[inline]
    fn first(&self) -> Option<CorpusId> {
        self.inner.first()
    }

    #[inline]
    fn last(&self) -> Option<CorpusId> {
        self.inner.last()
    }

    /// Get the nth corpus id; considers only enabled testcases
    #[inline]
    fn nth(&self, nth: usize) -> CorpusId {
        self.inner.nth(nth)
    }
    /// Get the nth corpus id; considers both enabled and disabled testcases
    #[inline]
    fn nth_from_all(&self, nth: usize) -> CorpusId {
        self.inner.nth_from_all(nth)
    }

    fn load_input_into(&self, testcase: &mut Testcase<Self::Input>) -> Result<(), Error> {
        if testcase.input_mut().is_none() {
            let Some(file_path) = testcase.file_path().as_ref() else {
                return Err(Error::illegal_argument(
                    "No file path set for testcase. Could not load inputs.",
                ));
            };
            let input = I::from_file(file_path)?;
            testcase.set_input(input);
        }
        Ok(())
    }

    fn store_input_from(&self, testcase: &Testcase<Self::Input>) -> Result<(), Error> {
        // Store the input to disk
        let Some(file_path) = testcase.file_path() else {
            return Err(Error::illegal_argument(
                "No file path set for testcase. Could not store input to disk.",
            ));
        };
        let Some(input) = testcase.input() else {
            return Err(Error::illegal_argument(
                "No input available for testcase. Could not store anything.",
            ));
        };
        input.to_file(file_path)
    }
}

impl<I> HasTestcase for InMemoryOnDiskCorpus<I>
where
    I: Input,
{
    fn testcase(
        &self,
        id: CorpusId,
    ) -> Result<core::cell::Ref<Testcase<<Self as Corpus>::Input>>, Error> {
        Ok(self.get(id)?.borrow())
    }

    fn testcase_mut(
        &self,
        id: CorpusId,
    ) -> Result<core::cell::RefMut<Testcase<<Self as Corpus>::Input>>, Error> {
        Ok(self.get(id)?.borrow_mut())
    }
}

impl<I> InMemoryOnDiskCorpus<I> {
    /// Creates an [`InMemoryOnDiskCorpus`].
    ///
    /// This corpus stores all testcases to disk, and keeps all of them in memory, as well.
    ///
    /// By default, it stores metadata for each [`Testcase`] as prettified json.
    /// Metadata will be written to a file named `.<testcase>.metadata`
    /// The metadata may include objective reason, specific information for a fuzz job, and more.
    ///
    /// If you don't want metadata, use [`InMemoryOnDiskCorpus::no_meta`].
    /// To pick a different metadata format, use [`InMemoryOnDiskCorpus::with_meta_format`].
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn new<P>(dir_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::_new(
            dir_path.as_ref(),
            Some(OnDiskMetadataFormat::JsonPretty),
            None,
            true,
        )
    }

    /// Creates the [`InMemoryOnDiskCorpus`] specifying the format in which `Metadata` will be saved to disk.
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn with_meta_format<P>(
        dir_path: P,
        meta_format: Option<OnDiskMetadataFormat>,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::_new(dir_path.as_ref(), meta_format, None, true)
    }

    /// Creates the [`InMemoryOnDiskCorpus`] specifying the format in which `Metadata` will be saved to disk
    /// and the prefix for the filenames.
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn with_meta_format_and_prefix<P>(
        dir_path: P,
        meta_format: Option<OnDiskMetadataFormat>,
        prefix: Option<String>,
        locking: bool,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::_new(dir_path.as_ref(), meta_format, prefix, locking)
    }

    /// Creates an [`InMemoryOnDiskCorpus`] that will not store .metadata files
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn no_meta<P>(dir_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::_new(dir_path.as_ref(), None, None, true)
    }

    /// Private fn to crate a new corpus at the given (non-generic) path with the given optional `meta_format`
    fn _new(
        dir_path: &Path,
        meta_format: Option<OnDiskMetadataFormat>,
        prefix: Option<String>,
        locking: bool,
    ) -> Result<Self, Error> {
        match fs::create_dir_all(dir_path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        Ok(InMemoryOnDiskCorpus {
            inner: InMemoryCorpus::new(),
            dir_path: dir_path.into(),
            meta_format,
            prefix,
            locking,
        })
    }

    /// Sets the filename for a [`Testcase`].
    /// If an error gets returned from the corpus (i.e., file exists), we'll have to retry with a different filename.
    #[inline]
    pub fn rename_testcase(
        &self,
        testcase: &mut Testcase<I>,
        filename: String,
    ) -> Result<(), Error> {
        if testcase.filename().is_some() {
            // We are renaming!

            let old_filename = testcase.filename_mut().take().unwrap();
            let new_filename = filename;

            // Do operations below when new filename is specified
            if old_filename == new_filename {
                *testcase.filename_mut() = Some(old_filename);
                return Ok(());
            }

            if self.locking {
                let new_lock_filename = format!(".{new_filename}.lafl_lock");

                // Try to create lock file for new testcases
                if let Err(err) = create_new(self.dir_path.join(&new_lock_filename)) {
                    *testcase.filename_mut() = Some(old_filename);
                    return Err(Error::illegal_state(format!(
                        "Unable to create lock file {new_lock_filename} for new testcase: {err}"
                    )));
                }
            }

            let new_file_path = self.dir_path.join(&new_filename);

            fs::rename(testcase.file_path().as_ref().unwrap(), &new_file_path)?;

            let new_metadata_path = {
                if let Some(old_metadata_path) = testcase.metadata_path() {
                    // We have metadata. Let's rename it.
                    let new_metadata_path = self.dir_path.join(format!(".{new_filename}.metadata"));
                    fs::rename(old_metadata_path, &new_metadata_path)?;

                    Some(new_metadata_path)
                } else {
                    None
                }
            };

            *testcase.metadata_path_mut() = new_metadata_path;
            *testcase.filename_mut() = Some(new_filename);
            *testcase.file_path_mut() = Some(new_file_path);

            Ok(())
        } else {
            Err(Error::illegal_argument(
                "Cannot rename testcase without name!",
            ))
        }
    }

    fn save_testcase(&self, testcase: &mut Testcase<I>, id: CorpusId) -> Result<(), Error>
    where
        I: Input,
    {
        let file_name_orig = testcase.filename_mut().take().unwrap_or_else(|| {
            // TODO walk entry metadata to ask for pieces of filename (e.g. :havoc in AFL)
            testcase.input().as_ref().unwrap().generate_name(Some(id))
        });

        // New testcase, we need to save it.
        let mut file_name = file_name_orig.clone();

        let mut ctr = 2;
        let file_name = if self.locking {
            loop {
                let lockfile_name = format!(".{file_name}.lafl_lock");
                let lockfile_path = self.dir_path.join(lockfile_name);

                if try_create_new(lockfile_path)?.is_some() {
                    break file_name;
                }

                file_name = format!("{file_name_orig}-{ctr}");
                ctr += 1;
            }
        } else {
            file_name
        };

        if testcase.file_path().is_none() {
            *testcase.file_path_mut() = Some(self.dir_path.join(&file_name));
        }
        *testcase.filename_mut() = Some(file_name);

        if self.meta_format.is_some() {
            let metafile_name = format!(".{}.metadata", testcase.filename().as_ref().unwrap());
            let metafile_path = self.dir_path.join(&metafile_name);
            let mut tmpfile_path = metafile_path.clone();
            tmpfile_path.set_file_name(format!(".{metafile_name}.tmp",));

            let ondisk_meta = OnDiskMetadata {
                metadata: testcase.metadata_map(),
                exec_time: testcase.exec_time(),
            };

            let mut tmpfile = File::create(&tmpfile_path)?;

            let json_error =
                |err| Error::serialize(format!("Failed to json-ify metadata: {err:?}"));

            let serialized = match self.meta_format.as_ref().unwrap() {
                OnDiskMetadataFormat::Postcard => postcard::to_allocvec(&ondisk_meta)?,
                OnDiskMetadataFormat::Json => {
                    serde_json::to_vec(&ondisk_meta).map_err(json_error)?
                }
                OnDiskMetadataFormat::JsonPretty => {
                    serde_json::to_vec_pretty(&ondisk_meta).map_err(json_error)?
                }
                #[cfg(feature = "gzip")]
                OnDiskMetadataFormat::JsonGzip => GzipCompressor::new()
                    .compress(&serde_json::to_vec_pretty(&ondisk_meta).map_err(json_error)?),
            };
            tmpfile.write_all(&serialized)?;
            fs::rename(&tmpfile_path, &metafile_path)?;
            *testcase.metadata_path_mut() = Some(metafile_path);
        }

        self.store_input_from(testcase)?;
        Ok(())
    }

    fn remove_testcase(&self, testcase: &Testcase<I>) -> Result<(), Error> {
        if let Some(filename) = testcase.filename() {
            fs::remove_file(self.dir_path.join(filename))?;
            if self.meta_format.is_some() {
                fs::remove_file(self.dir_path.join(format!(".{filename}.metadata")))?;
            }
            // also try to remove the corresponding `.lafl_lock` file if it still exists
            // (even though it shouldn't exist anymore, at this point in time)
            drop(fs::remove_file(
                self.dir_path.join(format!(".{filename}.lafl_lock")),
            ));
        }
        Ok(())
    }

    /// Path to the corpus directory associated with this corpus
    #[must_use]
    pub fn dir_path(&self) -> &PathBuf {
        &self.dir_path
    }
}

#[cfg(test)]
mod tests {
    use std::{env, fs, io::Write};

    use super::{create_new, try_create_new};

    #[test]
    fn test() {
        let tmp = env::temp_dir();
        let path = tmp.join("testfile.tmp");
        _ = fs::remove_file(&path);
        let mut f = create_new(&path).unwrap();
        f.write_all(&[0; 1]).unwrap();

        match try_create_new(&path) {
            Ok(None) => (),
            Ok(_) => panic!("File {path:?} did not exist even though it should have?"),
            Err(e) => panic!("An unexpected error occurred: {e}"),
        };
        drop(f);
        fs::remove_file(path).unwrap();
    }
}
