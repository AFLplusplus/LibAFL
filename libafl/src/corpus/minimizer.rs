#![allow(missing_docs)]

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{hash::Hash, marker::PhantomData};

use hashbrown::{HashMap, HashSet};
use num_traits::ToPrimitive;
use z3::{ast::Bool, Config, Context, Optimize};

use crate::{
    bolts::AsIter,
    corpus::Corpus,
    events::EventManager,
    executors::{Executor, HasObservers},
    inputs::Input,
    observers::{MapObserver, ObserversTuple},
    schedulers::{LenTimeMulTestcaseScore, Scheduler, TestcaseScore},
    state::{HasCorpus, HasMetadata},
    Error, Evaluator, HasScheduler,
};

pub trait CorpusMinimizer<I, S>
where
    I: Input,
    S: HasCorpus<I>,
{
    fn minimize<CS, EX, EM, OT, Z>(
        &self,
        fuzzer: &mut Z,
        executor: &mut EX,
        manager: &mut EM,
        state: &mut S,
    ) -> Result<(), Error>
    where
        CS: Scheduler<I, S>,
        EX: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
        EM: EventManager<EX, I, S, Z>,
        OT: ObserversTuple<I, S>,
        Z: Evaluator<EX, EM, I, S> + HasScheduler<CS, I, S>;
}

#[derive(Debug)]
pub struct MapCorpusMinimizer<E, I, O, S, TS>
where
    E: Copy + Hash + Eq,
    I: Input,
    for<'a> O: MapObserver<Entry = E> + AsIter<'a, Item = E>,
    S: HasMetadata + HasCorpus<I>,
    TS: TestcaseScore<I, S>,
{
    obs_name: String,
    phantom: PhantomData<(E, I, O, S, TS)>,
}

pub type StdCorpusMinimizer<E, I, O, S> =
    MapCorpusMinimizer<E, I, O, S, LenTimeMulTestcaseScore<I, S>>;

impl<E, I, O, S, TS> MapCorpusMinimizer<E, I, O, S, TS>
where
    E: Copy + Hash + Eq,
    I: Input,
    for<'a> O: MapObserver<Entry = E> + AsIter<'a, Item = E>,
    S: HasMetadata + HasCorpus<I>,
    TS: TestcaseScore<I, S>,
{
    pub fn new(obs: &O) -> Self {
        Self {
            obs_name: obs.name().to_string(),
            phantom: PhantomData,
        }
    }
}

impl<E, I, O, S, TS> CorpusMinimizer<I, S> for MapCorpusMinimizer<E, I, O, S, TS>
where
    E: Copy + Hash + Eq,
    I: Input,
    for<'a> O: MapObserver<Entry = E> + AsIter<'a, Item = E>,
    S: HasMetadata + HasCorpus<I>,
    TS: TestcaseScore<I, S>,
{
    fn minimize<CS, EX, EM, OT, Z>(
        &self,
        fuzzer: &mut Z,
        executor: &mut EX,
        manager: &mut EM,
        state: &mut S,
    ) -> Result<(), Error>
    where
        CS: Scheduler<I, S>,
        EX: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
        EM: EventManager<EX, I, S, Z>,
        OT: ObserversTuple<I, S>,
        Z: Evaluator<EX, EM, I, S> + HasScheduler<CS, I, S>,
    {
        let cfg = Config::default();
        let ctx = Context::new(&cfg);
        let opt = Optimize::new(&ctx);

        let mut seed_exprs = HashMap::new();
        let mut cov_map = HashMap::new();

        for idx in 0..state.corpus().count() {
            let (weight, input) = {
                let mut testcase = state.corpus().get(idx)?.borrow_mut();
                let weight = TS::compute(&mut *testcase, state)?
                    .to_u64()
                    .expect("Weight must be computable.");
                let input = testcase
                    .input()
                    .as_ref()
                    .expect("Input must be available.")
                    .clone();
                (weight, input)
            };
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

            for (i, e) in obs.as_iter().copied().enumerate() {
                cov_map
                    .entry(i)
                    .or_insert_with(|| HashMap::new())
                    .entry(e)
                    .or_insert_with(|| HashSet::new())
                    .insert(seed_expr.clone());
            }

            seed_exprs.insert(seed_expr, (idx, weight));
        }

        for (_, cov) in cov_map {
            for (_, seeds) in cov {
                if let Some(reduced) = seeds.into_iter().reduce(|s1, s2| s1 | s2) {
                    opt.assert(&reduced);
                }
            }
        }
        for (seed, (_, weight)) in &seed_exprs {
            opt.assert_soft(&!seed, *weight, None);
        }

        opt.check(&[]);

        let res = if let Some(model) = opt.get_model() {
            let mut removed = Vec::with_capacity(state.corpus().count());
            for (seed, (idx, _)) in seed_exprs {
                if !model.eval(&seed, true).unwrap().as_bool().unwrap() {
                    removed.push(idx);
                }
            }
            // reverse order; if indexes are stored in a vec, we need to remove from back to front
            removed.sort_unstable_by(|idx1, idx2| idx2.cmp(idx1));
            for idx in removed {
                let removed = state.corpus_mut().remove(idx)?;
                fuzzer.scheduler_mut().on_remove(state, idx, &removed)?;
            }
            Ok(())
        } else {
            Err(Error::unknown("Corpus minimization failed; unsat."))
        };

        res
    }
}
