use grammartec::{chunkstore::ChunkStore, context::Context};
use serde::{Deserialize, Serialize};
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
    state::{HasClientPerfStats, HasMetadata},
    Error,
};

#[derive(Serialize, Deserialize)]
pub struct NautilusChunksMetadata {
    pub cks: ChunkStore,
}

crate::impl_serdeany!(NautilusChunksMetadata);

impl NautilusChunksMetadata {
    #[must_use]
    pub fn new(work_dir: String) -> Self {
        create_dir_all(format!("{}/outputs/chunks", &work_dir))
            .expect("Could not create folder in workdir");
        Self {
            cks: ChunkStore::new(work_dir),
        }
    }
}

pub struct NautilusFeedback<'a> {
    ctx: &'a Context,
}

impl<'a> NautilusFeedback<'a> {
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
    S: HasMetadata + HasClientPerfStats,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &NautilusInput,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<NautilusInput, S>,
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
        meta.cks.add_tree(input.tree, &self.ctx);
        Ok(())
    }

    fn discard_metadata(&mut self, _state: &mut S, _input: &NautilusInput) -> Result<(), Error> {
        Ok(())
    }
}
