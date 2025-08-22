use libafl::{
    corpus::{InMemoryOnDiskCorpus, OnDiskCorpus},
    events::{
        ClientDescription, EventFirer, EventReceiver, EventRestarter, ProgressReporter, SendExiting,
    },
    inputs::BytesInput,
    state::StdState,
    Error,
};
use libafl_bolts::rands::StdRand;

use crate::{instance::Instance, options::FuzzerOptions};
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

    pub fn run<EM>(
        &self,
        state: Option<ClientState>,
        mgr: EM,
        client_description: ClientDescription,
    ) -> Result<(), Error>
    where
        EM: EventFirer<BytesInput, ClientState>
            + EventRestarter<ClientState>
            + ProgressReporter<ClientState>
            + SendExiting
            + EventReceiver<BytesInput, ClientState>,
    {
        let instance = Instance::builder()
            .options(self.options)
            .mgr(mgr)
            .client_description(client_description);

        instance.build().run(state)
    }
}
