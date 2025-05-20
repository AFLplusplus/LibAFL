use alloc::{
    fmt::Debug,
    string::{String, ToString},
    vec,
};
use core::{hash::BuildHasherDefault, marker::PhantomData};

use ahash::AHasher;
use hashbrown::HashMap;
use log::Level;
use thiserror::Error;

use crate::file::FileReader;

type Hasher = BuildHasherDefault<AHasher>;

#[derive(Debug)]
pub struct Env<R: FileReader> {
    envs: HashMap<String, String, Hasher>,
    phantom: PhantomData<R>,
}

impl<R: FileReader> Env<R> {
    /* Environment variable buffer size, should be larger than single largest env variable */
    const BUFFER_SIZE: usize = 131072;
    /* Expected maximum number of environment variables to initialize hash table */
    const MAX_ENVS: usize = 4096;

    pub fn initialize() -> Result<Env<R>, EnvError<R>> {
        let mut reader = R::new(c"/proc/self/environ").map_err(EnvError::FailedToCreateReader)?;

        let mut buffer = vec![0u8; Self::BUFFER_SIZE];

        let mut envs = HashMap::<String, String, Hasher>::with_capacity_and_hasher(
            Self::MAX_ENVS,
            Hasher::default(),
        );

        let mut start = 0;
        let mut bytes_read = 0;
        loop {
            let skip = bytes_read - start;
            start = 0;
            bytes_read = reader
                .read(&mut buffer[skip..])
                .map_err(EnvError::FailedToRead)?
                + skip;

            let mut i = 0;

            while i < bytes_read {
                if buffer[i] == 0 {
                    if i == start {
                        /* We found the null string at the end */
                        return Ok(Env {
                            envs,
                            phantom: PhantomData,
                        });
                    }

                    let pair = String::from_utf8_lossy(&buffer[start..i]).to_string();
                    log::debug!("pair: {pair}");

                    let (key, value) = pair
                        .split_once('=')
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .ok_or(EnvError::Split(pair))?;
                    log::debug!("key: {key} value: {value}");

                    envs.insert(key, value);
                    start = i + 1;
                }
                i += 1;
            }
            buffer.copy_within(start..bytes_read, 0);

            if bytes_read == 0 {
                if start == bytes_read {
                    break;
                }
                let fragment = String::from_utf8_lossy(&buffer[start..bytes_read]).to_string();
                return Err(EnvError::StringFragment(fragment));
            }
        }
        Ok(Env {
            envs,
            phantom: PhantomData,
        })
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.envs.get(name).map(|s| s.as_str())
    }

    pub fn log_level(&self) -> Option<Level> {
        self.get("RUST_LOG").and_then(|s| s.parse().ok())
    }
}

impl<R: FileReader> IntoIterator for Env<R> {
    type Item = (String, String);
    type IntoIter = hashbrown::hash_map::IntoIter<String, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.envs.into_iter()
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum EnvError<R: FileReader> {
    #[error("Failed to create reader: {0}")]
    FailedToCreateReader(R::Error),
    #[error("Failed to read: {0}")]
    FailedToRead(R::Error),
    #[error("Failed to split")]
    Split(String),
    #[error("String framgent: {0}")]
    StringFragment(String),
}
