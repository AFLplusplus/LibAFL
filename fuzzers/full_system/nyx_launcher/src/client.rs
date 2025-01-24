use libafl::{
    corpus::{InMemoryOnDiskCorpus, OnDiskCorpus},
    events::ClientDescription,
    inputs::BytesInput,
    monitors::Monitor,
    state::StdState,
    Error,
};
use libafl_bolts::rands::StdRand;

use crate::{
    instance::{ClientMgr, Instance},
    options::FuzzerOptions,
};

#[allow(clippy::module_name_repetitions)]
pub type ClientState =
    StdState<InMemoryOnDiskCorpus<BytesInput>, BytesInput, StdRand, OnDiskCorpus<BytesInput>>;

pub struct Client<'a> {
    options: &'a FuzzerOptions,
}

impl Client<'_> {
    pub fn new(options: &FuzzerOptions) -> Client {
        Client { options }
    }

    pub fn run<M: Monitor>(
        &self,
        state: Option<ClientState>,
        mgr: ClientMgr<M>,
        client_description: ClientDescription,
    ) -> Result<(), Error> {
        let instance = Instance::builder()
            .options(self.options)
            .mgr(mgr)
            .client_description(client_description);

        instance.build().run(state)
    }
}
