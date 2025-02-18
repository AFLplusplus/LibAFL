//! The replay stage can scan all inputs and executes them once per input

use alloc::{
    borrow::{Cow, ToOwned},
    string::ToString,
    vec::Vec,
};
use core::marker::PhantomData;

use hashbrown::HashSet;
use libafl_bolts::{impl_serdeany, Named};
use serde::{Deserialize, Serialize};

use crate::{
    corpus::{Corpus, CorpusId},
    stages::Stage,
    state::{HasCorpus, HasSolutions},
    Error, Evaluator,
};

/// Replay all inputs
#[derive(Debug)]
pub struct ReplayStage<I> {
    name: Cow<'static, str>,
    restart_helper: ReplayRestartingHelper,
    phantom: PhantomData<I>,
}

impl<I> Default for ReplayStage<I> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I> Named for ReplayStage<I> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// Restart helper for replay stage
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ReplayRestartingHelper {
    done_corpus: HashSet<CorpusId>,
    done_solution: HashSet<CorpusId>,
}

impl ReplayRestartingHelper {
    /// constructor
    #[must_use]
    pub fn new() -> Self {
        Self {
            done_corpus: HashSet::default(),
            done_solution: HashSet::default(),
        }
    }

    /// clear history
    pub fn clear(&mut self) {
        self.done_corpus.clear();
        self.done_solution.clear();
    }

    /// check we've scaned this corpus entry
    pub fn corpus_probe(&mut self, id: &CorpusId) -> bool {
        self.done_corpus.contains(id)
    }

    /// check we've scaned this solution entry
    pub fn solution_probe(&mut self, id: &CorpusId) -> bool {
        self.done_solution.contains(id)
    }

    /// mark this corpus entry as finished
    pub fn corpus_finish(&mut self, id: CorpusId) {
        self.done_corpus.insert(id);
    }

    /// mark this solution entry as finished
    pub fn solution_finish(&mut self, id: CorpusId) {
        self.done_solution.insert(id);
    }
}

impl_serdeany!(ReplayRestartingHelper);

/// The counter for giving this stage unique id
static mut REPLAY_STAGE_ID: usize = 0;
/// The name for tracing stage
pub static REPLAY_STAGE_NAME: &str = "tracing";

impl<I> ReplayStage<I> {
    #[must_use]
    /// Create a new replay stage
    pub fn new() -> Self {
        // unsafe but impossible that you create two threads both instantiating this instance
        let stage_id = unsafe {
            let ret = REPLAY_STAGE_ID;
            REPLAY_STAGE_ID += 1;
            ret
        };

        Self {
            name: Cow::Owned(REPLAY_STAGE_NAME.to_owned() + ":" + stage_id.to_string().as_ref()),
            restart_helper: ReplayRestartingHelper::new(),
            phantom: PhantomData,
        }
    }
}

impl<E, EM, I, S, Z> Stage<E, EM, S, Z> for ReplayStage<I>
where
    S: HasCorpus<I> + HasSolutions<I>,
    Z: Evaluator<E, EM, I, S>,
    I: Clone,
{
    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        self.restart_helper.clear();
        Ok(())
    }

    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let corpus_ids: Vec<CorpusId> = state.corpus().ids().collect();
        let solution_ids: Vec<CorpusId> = state.solutions().ids().collect();
        println!("{:?}", corpus_ids);
        println!("{:?}", solution_ids);

        for id in corpus_ids {
            if self.restart_helper.corpus_probe(&id) {
                continue;
            }
            log::info!("Replaying corpus: {id}");
            let input = {
                let mut tc = state.corpus().get(id)?.borrow_mut();
                let input = tc.load_input(state.corpus())?;
                input.clone()
            };

            fuzzer.evaluate_input(state, executor, manager, &input)?;

            self.restart_helper.corpus_finish(id);
        }

        for id in solution_ids {
            if self.restart_helper.solution_probe(&id) {
                continue;
            }
            log::info!("Replaying solution: {id}");
            let input = {
                let mut tc = state.corpus().get(id)?.borrow_mut();
                let input = tc.load_input(state.corpus())?;
                input.clone()
            };

            fuzzer.evaluate_input(state, executor, manager, &input)?;

            self.restart_helper.solution_finish(id);
        }

        Ok(())
    }
}
