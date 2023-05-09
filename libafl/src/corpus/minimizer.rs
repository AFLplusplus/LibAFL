//! Whole corpus minimizers, for reducing the number of samples/the total size/the average runtime
//! of your corpus.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{hash::Hash, marker::PhantomData};

use hashbrown::{HashMap, HashSet};
use num_traits::ToPrimitive;
use z3::{ast::Bool, Config, Context, Optimize};

use crate::{
    bolts::{
        tuples::{MatchName, Named},
        AsIter,
    },
    corpus::Corpus,
    executors::{Executor, HasObservers},
    observers::{MapObserver, ObserversTuple},
    schedulers::{LenTimeMulTestcaseScore, RemovableScheduler, Scheduler, TestcaseScore},
    state::{HasCorpus, HasMetadata, UsesState},
    Error, HasScheduler,
};

/// `CorpusMinimizers` minimize corpora according to internal logic. See various implementations for
/// details.
pub trait CorpusMinimizer<E>
where
    E: UsesState,
    E::State: HasCorpus,
{
    /// Minimize the corpus of the provided state.
    fn minimize<CS, EM, Z>(
        &self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        state: &mut E::State,
    ) -> Result<(), Error>
    where
        E: Executor<EM, Z> + HasObservers,
        CS: Scheduler<State = E::State> + RemovableScheduler, // schedulers that has on_remove/on_replace only!
        EM: UsesState<State = E::State>,
        Z: HasScheduler<Scheduler = CS, State = E::State>;
}

/// Minimizes a corpus according to coverage maps, weighting by the specified `TestcaseScore`.
///
/// Algorithm based on WMOPT: <https://hexhive.epfl.ch/publications/files/21ISSTA2.pdf>
#[derive(Debug)]
pub struct MapCorpusMinimizer<E, O, T, TS>
where
    E: UsesState,
    E::State: HasCorpus + HasMetadata,
    TS: TestcaseScore<E::State>,
{
    obs_name: String,
    phantom: PhantomData<(E, O, T, TS)>,
}

/// Standard corpus minimizer, which weights inputs by length and time.
pub type StdCorpusMinimizer<E, O, T> =
    MapCorpusMinimizer<E, O, T, LenTimeMulTestcaseScore<<E as UsesState>::State>>;

impl<E, O, T, TS> MapCorpusMinimizer<E, O, T, TS>
where
    E: UsesState,
    E::State: HasCorpus + HasMetadata,
    TS: TestcaseScore<E::State>,
{
    /// Constructs a new `MapCorpusMinimizer` from a provided observer. This observer will be used
    /// in the future to get observed maps from an executed input.
    pub fn new(obs: &O) -> Self
    where
        O: Named,
    {
        Self {
            obs_name: obs.name().to_string(),
            phantom: PhantomData,
        }
    }
}

impl<E, O, T, TS> CorpusMinimizer<E> for MapCorpusMinimizer<E, O, T, TS>
where
    E: UsesState,
    for<'a> O: MapObserver<Entry = T> + AsIter<'a, Item = T>,
    E::State: HasMetadata + HasCorpus,
    T: Copy + Hash + Eq,
    TS: TestcaseScore<E::State>,
{
    fn minimize<CS, EM, Z>(
        &self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        state: &mut E::State,
    ) -> Result<(), Error>
    where
        E: Executor<EM, Z> + HasObservers,
        CS: Scheduler<State = E::State> + RemovableScheduler,
        EM: UsesState<State = E::State>,
        Z: HasScheduler<Scheduler = CS, State = E::State>,
    {
        let cfg = Config::default();
        let ctx = Context::new(&cfg);
        let opt = Optimize::new(&ctx);

        let mut seed_exprs = HashMap::new();
        let mut cov_map = HashMap::new();

        let mut cur_id = state.corpus().first();
        while let Some(idx) = cur_id {
            let (weight, input) = {
                let mut testcase = state.corpus().get(idx)?.borrow_mut();
                let weight = TS::compute(state, &mut *testcase)?
                    .to_u64()
                    .expect("Weight must be computable.");
                let input = testcase
                    .input()
                    .as_ref()
                    .expect("Input must be available.")
                    .clone();
                (weight, input)
            };

            // Execute the input; we cannot rely on the metadata already being present.
            executor.observers_mut().pre_exec_all(state, &input)?;
            let kind = executor.run_target(fuzzer, state, manager, &input)?;
            executor
                .observers_mut()
                .post_exec_all(state, &input, &kind)?;

            let seed_expr = Bool::fresh_const(&ctx, "seed");
            let obs: &O = executor
                .observers()
                .match_name::<O>(&self.obs_name)
                .expect("Observer must be present.");

            // Store coverage, mapping coverage map indices to hit counts (if present) and the
            // associated seeds for the map indices with those hit counts.
            for (i, e) in obs.as_iter().copied().enumerate() {
                if e != obs.initial() {
                    cov_map
                        .entry(i)
                        .or_insert_with(HashMap::new)
                        .entry(e)
                        .or_insert_with(HashSet::new)
                        .insert(seed_expr.clone());
                }
            }

            // Keep track of that seed's index and weight
            seed_exprs.insert(seed_expr, (idx, weight));

            cur_id = state.corpus().next(idx);
        }

        for (_, cov) in cov_map {
            for (_, seeds) in cov {
                // At least one seed for each hit count of each coverage map index
                if let Some(reduced) = seeds.into_iter().reduce(|s1, s2| s1 | s2) {
                    opt.assert(&reduced);
                }
            }
        }
        for (seed, (_, weight)) in &seed_exprs {
            // opt will attempt to minimise the number of violated assertions.
            //
            // To tell opt to minimize the number of seeds, we tell opt to maximize the number of
            // not seeds.
            //
            // Additionally, each seed has a weight associated with them; the higher, the more z3
            // doesn't want to violate the assertion. Thus, inputs which have higher weights will be
            // less likely to appear in the final corpus -- provided all their coverage points are
            // hit by at least one other input.
            opt.assert_soft(&!seed, *weight, None);
        }

        // Perform the optimization!
        opt.check(&[]);

        let res = if let Some(model) = opt.get_model() {
            let mut removed = Vec::with_capacity(state.corpus().count());
            for (seed, (idx, _)) in seed_exprs {
                // if the model says the seed isn't there, mark it for deletion
                if !model.eval(&seed, true).unwrap().as_bool().unwrap() {
                    removed.push(idx);
                }
            }
            // reverse order; if indexes are stored in a vec, we need to remove from back to front
            removed.sort_unstable_by(|idx1, idx2| idx2.cmp(idx1));
            for idx in removed {
                let removed = state.corpus_mut().remove(idx)?;
                // scheduler needs to know we've removed the input, or it will continue to try
                // to use now-missing inputs
                fuzzer
                    .scheduler_mut()
                    .on_remove(state, idx, &Some(removed))?;
            }
            Ok(())
        } else {
            Err(Error::unknown("Corpus minimization failed; unsat."))
        };

        res
    }
}
