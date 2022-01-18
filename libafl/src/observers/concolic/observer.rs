use crate::{
    bolts::tuples::Named,
    observers::{
        concolic::{serialization_format::MessageFileReader, ConcolicMetadata},
        Observer,
    },
    state::HasCorpus,
};
use serde::{Deserialize, Serialize};

/// A standard [`ConcolicObserver`] observer, observing constraints written into a memory buffer.
#[derive(Serialize, Deserialize, Debug)]
pub struct ConcolicObserver<'map> {
    #[serde(skip)]
    map: &'map [u8],
    name: String,
}

impl<'map, S> Observer<S> for ConcolicObserver<'map> where S: HasCorpus {}

impl<'map> ConcolicObserver<'map> {
    /// Create the concolic observer metadata for this run
    #[must_use]
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
