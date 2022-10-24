//! Nautilus grammar mutator, see <https://github.com/nautilus-fuzz/nautilus>
use alloc::string::String;
use core::{fmt::Debug, marker::PhantomData};
use std::fs::create_dir_all;

use grammartec::{chunkstore::ChunkStore, context::Context};
use serde::{Deserialize, Serialize};
use serde_json;

use crate::{
    bolts::tuples::Named,
    corpus::Testcase,
    events::EventFirer,
    executors::ExitKind,
    feedbacks::Feedback,
    generators::NautilusContext,
    inputs::NautilusInput,
    observers::ObserversTuple,
    prelude::UsesInput,
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
pub struct NautilusFeedback<'a, S> {
    ctx: &'a Context,
    phantom: PhantomData<S>,
}

impl<S> Debug for NautilusFeedback<'_, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NautilusFeedback {{}}")
    }
}

impl<'a, S> NautilusFeedback<'a, S> {
    /// Create a new [`NautilusFeedback`]
    #[must_use]
    pub fn new(context: &'a NautilusContext) -> Self {
        Self {
            ctx: &context.ctx,
            phantom: PhantomData,
        }
    }
}

impl<'a, S> Named for NautilusFeedback<'a, S> {
    fn name(&self) -> &str {
        "NautilusFeedback"
    }
}

impl<'a, S> Feedback<S> for NautilusFeedback<'a, S>
where
    S: HasMetadata + HasClientPerfMonitor + UsesInput<Input = NautilusInput>,
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
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
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
