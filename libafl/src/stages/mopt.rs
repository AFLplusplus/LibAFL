use core::marker::PhantomData;

use crate::{
    bolts::rands::Rand,
    corpus::Corpus,
    fuzzer::Evaluator,
    inputs::Input,
    mutators::{MOpt, MOptMode, MOptMutator, MutatorsTuple},
    stages::{MutationalStage, Stage},
    state::{HasClientPerfStats, HasCorpus, HasMetadata, HasRand, HasSolutions},
    Error,
};

const PERIOD_PILOT_COEF: f64 = 5000.0;

#[derive(Clone, Debug)]
pub struct MOptStage<C, E, EM, I, M, MT, R, S, SC, Z>
where
    C: Corpus<I>,
    M: MOptMutator<I, MT, R, S>,
    MT: MutatorsTuple<I, S>,
    I: Input,
    R: Rand,
    S: HasClientPerfStats + HasCorpus<C, I> + HasSolutions<SC, I> + HasRand<R> + HasMetadata,
    SC: Corpus<I>,
    Z: Evaluator<E, EM, I, S>,
{
    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(C, E, EM, I, MT, R, S, SC, Z)>,
}

impl<C, E, EM, I, M, MT, R, S, SC, Z> MutationalStage<C, E, EM, I, M, S, Z>
    for MOptStage<C, E, EM, I, M, MT, R, S, SC, Z>
where
    C: Corpus<I>,
    M: MOptMutator<I, MT, R, S>,
    MT: MutatorsTuple<I, S>,
    I: Input,
    R: Rand,
    S: HasClientPerfStats + HasCorpus<C, I> + HasSolutions<SC, I> + HasRand<R> + HasMetadata,
    SC: Corpus<I>,
    Z: Evaluator<E, EM, I, S>,
{
    /// The mutator, added to this stage
    #[inline]
    fn mutator(&self) -> &M {
        &self.mutator
    }

    /// The list of mutators, added to this stage (as mutable ref)
    #[inline]
    fn mutator_mut(&mut self) -> &mut M {
        &mut self.mutator
    }

    /// Gets the number of iterations as a random number
    fn iterations(&self, state: &mut S) -> usize {
        // TODO: we want to use calculate_score here

        1 + state.rand_mut().below(128) as usize
    }

    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_precision_loss,
        clippy::too_many_lines
    )]
    fn perform_mutational(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let key_module = state.metadata().get::<MOpt>().unwrap().key_module;

        match key_module {
            MOptMode::Corefuzzing => {
                let num = self.iterations(state);

                for stage_id in 0..num {
                    let mut input = state
                        .corpus()
                        .get(corpus_idx)?
                        .borrow_mut()
                        .load_input()?
                        .clone();

                    self.mutator_mut()
                        .mutate(state, &mut input, stage_id as i32)?;

                    let finds_before = state.corpus().count() + state.solutions().count();

                    let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, input)?;

                    self.mutator_mut()
                        .post_exec(state, stage_id as i32, corpus_idx)?;

                    let finds_after = state.corpus().count() + state.solutions().count();

                    let mopt = state.metadata_mut().get_mut::<MOpt>().unwrap();

                    mopt.core_time += 1;

                    if finds_after > finds_before {
                        let diff = finds_after - finds_before;
                        mopt.total_finds += diff;
                        for i in 0..mopt.operator_num {
                            if mopt.core_operator_ctr_this[i] > mopt.core_operator_ctr_last[i] {
                                mopt.core_operator_finds_this[i] += diff;
                            }
                        }
                    }

                    if mopt.core_time > mopt.period_core {
                        // Make a call to pso_update()
                        mopt.core_time = 0;
                        let total_finds = mopt.total_finds;
                        mopt.finds_before_switch = total_finds;
                        mopt.update_core_operator_ctr_pso();
                        mopt.pso_update()?;
                    }
                }
            }
            MOptMode::Pilotfuzzing => {
                let num = self.iterations(state);
                for stage_id in 0..num {
                    let mut input = state
                        .corpus()
                        .get(corpus_idx)?
                        .borrow_mut()
                        .load_input()?
                        .clone();

                    self.mutator_mut()
                        .mutate(state, &mut input, stage_id as i32)?;

                    let finds_before = state.corpus().count() + state.solutions().count();

                    let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, input)?;

                    self.mutator_mut()
                        .post_exec(state, stage_id as i32, corpus_idx)?;

                    let finds_after = state.corpus().count() + state.solutions().count();

                    let mopt = state.metadata_mut().get_mut::<MOpt>().unwrap();

                    mopt.pilot_time += 1;
                    let swarm_now = mopt.swarm_now;

                    if finds_after > finds_before {
                        let diff = finds_after - finds_before;
                        mopt.total_finds += diff;
                        for i in 0..mopt.operator_num {
                            if mopt.pilot_operator_ctr_this[swarm_now][i]
                                > mopt.pilot_operator_ctr_last[swarm_now][i]
                            {
                                mopt.pilot_operator_finds_this[swarm_now][i] += diff;
                            }
                        }
                    }

                    if mopt.pilot_time > mopt.period_pilot {
                        let new_finds = mopt.total_finds - mopt.finds_before_switch;
                        let f =
                            (new_finds as f64) / ((mopt.pilot_time as f64) / (PERIOD_PILOT_COEF));
                        mopt.swarm_fitness[swarm_now] = f;
                        mopt.pilot_time = 0;
                        let total_finds = mopt.total_finds;
                        mopt.finds_before_switch = total_finds;
                        mopt.update_pilot_operator_ctr_pso(swarm_now);

                        mopt.swarm_now += 1;

                        if mopt.swarm_now == mopt.swarm_num {
                            // Move to CORE_FUZING mode
                            mopt.key_module = MOptMode::Corefuzzing;

                            mopt.init_core_module()?;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl<C, E, EM, I, M, MT, R, S, SC, Z> Stage<E, EM, S, Z>
    for MOptStage<C, E, EM, I, M, MT, R, S, SC, Z>
where
    C: Corpus<I>,
    M: MOptMutator<I, MT, R, S>,
    MT: MutatorsTuple<I, S>,
    I: Input,
    R: Rand,
    S: HasClientPerfStats + HasCorpus<C, I> + HasSolutions<SC, I> + HasRand<R> + HasMetadata,
    SC: Corpus<I>,
    Z: Evaluator<E, EM, I, S>,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        self.perform_mutational(fuzzer, executor, state, manager, corpus_idx)
    }
}

impl<C, E, EM, I, M, MT, R, S, SC, Z> MOptStage<C, E, EM, I, M, MT, R, S, SC, Z>
where
    C: Corpus<I>,
    M: MOptMutator<I, MT, R, S>,
    MT: MutatorsTuple<I, S>,
    I: Input,
    R: Rand,
    S: HasClientPerfStats + HasCorpus<C, I> + HasSolutions<SC, I> + HasRand<R> + HasMetadata,
    SC: Corpus<I>,
    Z: Evaluator<E, EM, I, S>,
{
    /// Creates a new default mutational stage
    pub fn new(mutator: M, state: &mut S, swarm_num: usize) -> Result<Self, Error> {
        state.add_metadata::<MOpt>(MOpt::new(mutator.mutations().len(), swarm_num)?);
        Ok(Self {
            mutator,
            phantom: PhantomData,
        })
    }
}
