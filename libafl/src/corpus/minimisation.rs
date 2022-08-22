#![allow(missing_docs)]

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{hash::Hash, marker::PhantomData};
use std::time::{Duration, Instant};

use hashbrown::{HashMap, HashSet};
use z3::{ast::Bool, Config, Context, Optimize};

use crate::{
    bolts::{AsIter, HasLen},
    corpus::Corpus,
    events::EventManager,
    executors::{Executor, HasObservers},
    inputs::Input,
    observers::{MapObserver, ObserversTuple},
    schedulers::Scheduler,
    state::HasCorpus,
    Error, Evaluator, HasScheduler,
};

pub trait CorpusMinimiser<I, O>
where
    I: Input,
{
    fn new(obs: &O) -> Self;

    fn minimise<CS, EX, EM, OT, S, Z>(
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
        S: HasCorpus<I>,
        Z: Evaluator<EX, EM, I, S> + HasScheduler<CS, I, S>;
}

#[derive(Debug)]
pub struct MapCorpusMinimiser<I, O, W>
where
    I: Input,
    W: InputWeigher<I>,
{
    obs_name: String,
    phantom: PhantomData<(I, O, W)>,
}

pub type StdCorpusMinimiser<I, O> = MapCorpusMinimiser<I, O, TimeLenInputWeigher<I>>;

impl<E, I, O, W> CorpusMinimiser<I, O> for MapCorpusMinimiser<I, O, W>
where
    E: Copy + Hash + Eq,
    I: Input,
    for<'a> O: MapObserver<Entry = E> + AsIter<'a, Item = E>,
    W: InputWeigher<I>,
{
    fn new(obs: &O) -> Self {
        Self {
            obs_name: obs.name().to_string(),
            phantom: PhantomData,
        }
    }

    fn minimise<CS, EX, EM, OT, S, Z>(
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
        S: HasCorpus<I>,
        Z: Evaluator<EX, EM, I, S> + HasScheduler<CS, I, S>,
    {
        let cfg = Config::default();
        let ctx = Context::new(&cfg);
        let opt = Optimize::new(&ctx);

        let mut seed_exprs = HashMap::new();
        let mut cov_map = HashMap::new();

        for idx in 0..state.corpus().count() {
            let input = state
                .corpus()
                .get(idx)?
                .borrow()
                .input()
                .as_ref()
                .expect("Input should be present")
                .clone();
            executor.observers_mut().pre_exec_all(state, &input)?;
            let start = Instant::now();
            let kind = executor.run_target(fuzzer, state, manager, &input)?;
            let exec_time = Instant::now() - start;
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
            seed_exprs.insert(seed_expr, (idx, W::weigh_input(&input, exec_time)?));
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
            Err(Error::unknown("Corpus minimisation failed; unsat."))
        };

        res
    }
}

pub trait InputWeigher<I> {
    fn weigh_input(input: &I, execution_time: Duration) -> Result<u64, Error>;
}

#[derive(Debug)]
pub struct TimeInputWeigher<I> {
    phantom: PhantomData<I>,
}

impl<I> InputWeigher<I> for TimeInputWeigher<I> {
    fn weigh_input(_: &I, execution_time: Duration) -> Result<u64, Error> {
        Ok(execution_time.as_millis().try_into()?)
    }
}

#[derive(Debug)]
pub struct TimeLenInputWeigher<I>
where
    I: HasLen,
{
    phantom: PhantomData<I>,
}

impl<I> InputWeigher<I> for TimeLenInputWeigher<I>
where
    I: HasLen,
{
    fn weigh_input(input: &I, execution_time: Duration) -> Result<u64, Error> {
        Ok(TimeInputWeigher::weigh_input(input, execution_time)? * u64::try_from(input.len())?)
    }
}
