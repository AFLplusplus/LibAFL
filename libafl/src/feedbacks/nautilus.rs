//! Nautilus grammar mutator, see <https://github.com/nautilus-fuzz/nautilus>
use core::fmt::Debug;
use grammartec::{chunkstore::ChunkStore, context::Context};
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::create_dir_all;

use crate::{
    bolts::tuples::Named,
    corpus::Testcase,
    events::EventFirer,
    executors::ExitKind,
    feedbacks::Feedback,
    generators::NautilusContext,
    inputs::NautilusInput,
    observers::ObserversTuple,
    state::{HasClientPerfMonitor, HasMetadata},
    Error,
};

/// Metadata for Nautilus grammar mutator chunks
#[derive(Serialize, Deserialize)]
pub struct NautilusChunksMetadata {
    /// the chunk store
    pub cks: ChunkStore,
}

impl Debug for NautilusChunksMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NautilusChunksMetadata {{ {} }}",
            serde_json::to_string_pretty(self).unwrap(),
        )
    }
}

crate::impl_serdeany!(NautilusChunksMetadata);

impl NautilusChunksMetadata {
    /// Creates a new [`NautilusChunksMetadata`]
    #[must_use]
    pub fn new(work_dir: String) -> Self {
        create_dir_all(format!("{}/outputs/chunks", &work_dir))
            .expect("Could not create folder in workdir");
        Self {
            cks: ChunkStore::new(work_dir),
        }
    }
}

/// A nautilus feedback for grammar fuzzing
pub struct NautilusFeedback<'a> {
    ctx: &'a Context,
}

impl Debug for NautilusFeedback<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NautilusFeedback {{}}")
    }
}

impl<'a> NautilusFeedback<'a> {
    /// Create a new [`NautilusFeedback`]
    #[must_use]
    pub fn new(context: &'a NautilusContext) -> Self {
        Self { ctx: &context.ctx }
    }
}

impl<'a> Named for NautilusFeedback<'a> {
    fn name(&self) -> &str {
        "NautilusFeedback"
    }
}

impl<'a, S> Feedback<NautilusInput, S> for NautilusFeedback<'a>
where
    S: HasMetadata + HasClientPerfMonitor,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &NautilusInput,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<NautilusInput>,
        OT: ObserversTuple<NautilusInput, S>,
    {
        Ok(false)
    }

    fn append_metadata(
        &mut self,
        state: &mut S,
        testcase: &mut Testcase<NautilusInput>,
    ) -> Result<(), Error> {
        let input = testcase.load_input()?.clone();
        let meta = state
            .metadata_mut()
            .get_mut::<NautilusChunksMetadata>()
            .expect("NautilusChunksMetadata not in the state");
        meta.cks.add_tree(input.tree, self.ctx);
        Ok(())
    }

    fn discard_metadata(&mut self, _state: &mut S, _input: &NautilusInput) -> Result<(), Error> {
        Ok(())
    }
}
