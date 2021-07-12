use concolic::serialization_format::MessageFileReader;
use libafl::{bolts::tuples::Named, observers::Observer};
use serde::{Deserialize, Serialize};

use crate::metadata::ConcolicMetadata;

/// A standard [`ConcolicObserver`] observer, observing constraints written into a memory buffer.
#[derive(Serialize, Deserialize, Debug)]
pub struct ConcolicObserver<'map> {
    #[serde(skip)]
    map: &'map [u8],
    name: String,
}

impl<'map, I, S> Observer<I, S> for ConcolicObserver<'map> {}

impl<'map> ConcolicObserver<'map> {
    pub fn create_metadata_from_current_map(&self) -> ConcolicMetadata {
        let reader = MessageFileReader::from_length_prefixed_buffer(self.map)
            .expect("constructing the message reader from a memory buffer should not fail");
        ConcolicMetadata::from_buffer(reader.get_buffer().to_vec())
    }
}

impl<'map> Named for ConcolicObserver<'map> {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<'map> ConcolicObserver<'map> {
    /// Creates a new [`ConcolicObserver`] with the given name and memory buffer.
    #[must_use]
    pub fn new(name: String, map: &'map [u8]) -> Self {
        Self { map, name }
    }
}
