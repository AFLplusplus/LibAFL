//! The `MOpt` mutator scheduler, see <https://github.com/puppet-meteor/MOpt-AFL> and <https://www.usenix.org/conference/usenixsecurity19/presentation/lyu>
use alloc::{string::ToString, vec::Vec};

use crate::{
    bolts::{rands::Rand, rands::StdRand},
    inputs::Input,
    mutators::{ComposedByMutations, MutationResult, Mutator, MutatorsTuple, ScheduledMutator},
    state::{HasMetadata, HasRand},
    Error,
};
use core::{
    fmt::{self, Debug},
    marker::PhantomData,
};
use serde::{Deserialize, Serialize};

/// A Struct for managing MOpt-mutator parameters
/// There are 2 modes for `MOpt` scheduler, the core fuzzing mode and the pilot fuzzing mode
/// In short, in the pilot fuzzing mode, the fuzzer employs several `swarms` to compute the probability to choose the mutation operator
/// On the other hand, in the core fuzzing mode, the fuzzer chooses the best `swarms`, which was determined during the pilot fuzzing mode, to compute the probability to choose the operation operator
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MOpt {
    /// Random number generator
    pub rand: StdRand,
    /// The number of finds until the beginning of this core fuzzing mode
    pub finds_until_core_begin: usize,
    /// The number of total findings (unique crashes and unique interesting paths). This is equivalent to `state.corpus().count() + state.solutions().count()`;
    pub total_finds: usize,
    /// The number of finds until the beginning of this pilot fuzzing mode
    pub finds_until_pilot_begin: usize,
    /// The MOpt mode that we are currently using the pilot fuzzing mode or the core_fuzzing mode
    pub key_module: MOptMode,
    /// These w_* and g_* values are the coefficients for updating variables according to the PSO algorithms
    pub w_init: f64,
    pub w_end: f64,
    pub w_now: f64,
    pub g_now: i32,
    pub g_max: i32,
    /// The number of mutation operators
    pub operator_num: usize,
    /// The number of swarms that we want to employ during the pilot fuzzing mode
    pub swarm_num: usize,
    /// We'll generate testcases for `period_pilot` times before we call pso_update in core fuzzing module
    pub period_pilot: usize,
    /// We'll generate testcases for `period_core` times before we call pso_update in core fuzzing module
    pub period_core: usize,
    /// The number of testcases generated during this pilot fuzzing mode
    pub pilot_time: usize,
    /// The number of testcases generated during this core fuzzing mode
    pub core_time: usize,
    /// The swarm identifier that we are currently using in the pilot fuzzing mode
    pub swarm_now: usize,
    /// These are the parameters for the PSO algorithm
    x_now: Vec<Vec<f64>>,
    l_best: Vec<Vec<f64>>,
    eff_best: Vec<Vec<f64>>,
    g_best: Vec<f64>,
    v_now: Vec<Vec<f64>>,
    /// The probability that we want to use to choose the mutation operator.
    probability_now: Vec<Vec<f64>>,
    /// The fitness for each swarm, we'll calculate the fitness in the pilot fuzzing mode and use the best one in the core fuzzing mode
    pub swarm_fitness: Vec<f64>,
    /// (Pilot Mode) Finds by each operators. This vector is used in pso_update
    pub pilot_operator_finds_pso: Vec<Vec<usize>>,
    /// (Pilot Mode) Finds by each operator till now.
    pub pilot_operator_finds_this: Vec<Vec<usize>>,
    /// (Pilot Mode) The number of mutation operator used. This vector is used in pso_update
    pub pilot_operator_ctr_pso: Vec<Vec<usize>>,
    /// (Pilot Mode) The number of mutation operator used till now
    pub pilot_operator_ctr_this: Vec<Vec<usize>>,
    /// (Pilot Mode) The number of mutation operator used till last execution
    pub pilot_operator_ctr_last: Vec<Vec<usize>>,
    /// Vector used in pso_update
    pub operator_finds_puppet: Vec<usize>,
    /// (Core Mode) Finds by each operators. This vector is used in pso_update
    pub core_operator_finds_pso: Vec<usize>,
    /// (Core Mode) Finds by each operator till now.
    pub core_operator_finds_this: Vec<usize>,
    /// (Core Mode) The number of mutation operator used. This vector is used in pso_update
    pub core_operator_ctr_pso: Vec<usize>,
    /// (Core Mode) The number of mutation operator used till now
    pub core_operator_ctr_this: Vec<usize>,
    /// (Core Mode) The number of mutation operator used till last execution
    pub core_operator_ctr_last: Vec<usize>,
}

crate::impl_serdeany!(MOpt);

impl MOpt {
    #[must_use]
    pub fn new(operator_num: usize, swarm_num: usize) -> Self {
        Self {
            rand: StdRand::with_seed(0),
            finds_until_core_begin: 0,
            total_finds: 0,
            finds_until_pilot_begin: 0,
            key_module: MOptMode::Corefuzzing,
            w_init: 0.9,
            w_end: 0.3,
            w_now: 0.0,
            g_now: 0,
            g_max: 5000,
            operator_num,
            swarm_num,
            period_pilot: 50000,
            period_core: 500000,
            pilot_time: 0,
            core_time: 0,
            swarm_now: 0,
            x_now: vec![vec![0.0; operator_num]; swarm_num],
            l_best: vec![vec![0.0; operator_num]; swarm_num],
            eff_best: vec![vec![0.0; operator_num]; swarm_num],
            g_best: vec![0.0; operator_num],
            v_now: vec![vec![0.0; operator_num]; swarm_num],
            probability_now: vec![vec![0.0; operator_num]; swarm_num],
            swarm_fitness: vec![0.0; swarm_num],
            pilot_operator_finds_pso: vec![vec![0; operator_num]; swarm_num],
            pilot_operator_finds_this: vec![vec![0; operator_num]; swarm_num],
            pilot_operator_ctr_pso: vec![vec![0; operator_num]; swarm_num],
            pilot_operator_ctr_this: vec![vec![0; operator_num]; swarm_num],
            pilot_operator_ctr_last: vec![vec![0; operator_num]; swarm_num],
            operator_finds_puppet: vec![0; operator_num],
            core_operator_finds_pso: vec![0; operator_num],
            core_operator_finds_this: vec![0; operator_num],
            core_operator_ctr_pso: vec![0; operator_num],
            core_operator_ctr_this: vec![0; operator_num],
            core_operator_ctr_last: vec![0; operator_num],
        }
    }

    /// Get a float below the given `size` value times `0.001`.
    /// So `size` 100 will result in anything between `0` and 0.1`.
    #[inline]
    #[allow(clippy::cast_precision_loss)]
    pub fn rand_below(&mut self, size: u64) -> f64 {
        self.rand.below(size) as f64 * 0.001
    }

    /// Initialize `core_operator_*` values
    pub fn init_core_module(&mut self) -> Result<(), Error> {
        for i in 0..self.operator_num {
            self.core_operator_ctr_this[i] = self.core_operator_ctr_pso[i];
            self.core_operator_ctr_last[i] = self.core_operator_ctr_pso[i];
            self.core_operator_finds_this[i] = self.core_operator_finds_pso[i]
        }

        let mut swarm_eff = 0.0;
        let mut best_swarm = 0;
        for i in 0..self.swarm_num {
            if self.swarm_fitness[i] > swarm_eff {
                swarm_eff = self.swarm_fitness[i];
                best_swarm = i;
            }
        }

        self.swarm_now = best_swarm;
        Ok(())
    }

    #[inline]
    pub fn update_pilot_operator_ctr_last(&mut self, swarm_now: usize) {
        for i in 0..self.operator_num {
            self.pilot_operator_ctr_last[swarm_now][i] = self.pilot_operator_ctr_this[swarm_now][i]
        }
    }

    #[inline]
    pub fn update_core_operator_ctr_last(&mut self) {
        for i in 0..self.operator_num {
            self.core_operator_ctr_last[i] = self.core_operator_ctr_this[i];
        }
    }

    /// Finds the local optimum for each operator
    /// See <https://github.com/puppet-meteor/MOpt-AFL/blob/master/MOpt/afl-fuzz.c#L8709>

    #[allow(clippy::cast_precision_loss)]
    pub fn update_pilot_operator_ctr_pso(&mut self, swarm_now: usize) {
        let mut eff = 0.0;
        for i in 0..self.operator_num {
            if self.pilot_operator_ctr_this[swarm_now][i]
                > self.pilot_operator_ctr_pso[swarm_now][i]
            {
                eff = ((self.pilot_operator_finds_this[swarm_now][i]
                    - self.pilot_operator_finds_pso[swarm_now][i]) as f64)
                    / ((self.pilot_operator_ctr_this[swarm_now][i]
                        - self.pilot_operator_ctr_pso[swarm_now][i]) as f64)
            }

            if self.eff_best[swarm_now][i] < eff {
                self.eff_best[swarm_now][i] = eff;
                self.l_best[swarm_now][i] = self.x_now[swarm_now][i];
            }

            self.pilot_operator_finds_pso[swarm_now][i] =
                self.pilot_operator_finds_this[swarm_now][i];
            self.pilot_operator_ctr_pso[swarm_now][i] = self.pilot_operator_ctr_this[swarm_now][i];
        }
    }

    #[inline]
    pub fn update_core_operator_ctr_pso(&mut self) {
        for i in 0..self.operator_num {
            self.core_operator_finds_pso[i] = self.core_operator_finds_this[i];
            self.core_operator_ctr_pso[i] = self.core_operator_ctr_this[i];
        }
    }

    /// Update the PSO algorithm parameters
    /// See <https://github.com/puppet-meteor/MOpt-AFL/blob/master/MOpt/afl-fuzz.c#L10623>
    #[allow(clippy::cast_precision_loss)]
    pub fn pso_update(&mut self) -> Result<(), Error> {
        self.g_now += 1;
        if self.g_now > self.g_max {
            self.g_now = 0;
        }
        self.w_now = (self.w_init - self.w_end) * f64::from(self.g_max - self.g_now)
            / f64::from(self.g_max)
            + self.w_end;

        let mut operator_find_sum = 0;

        for i in 0..self.operator_num {
            self.operator_finds_puppet[i] = self.core_operator_ctr_pso[i];

            for j in 0..self.swarm_num {
                self.operator_finds_puppet[i] += self.pilot_operator_finds_pso[j][i];
            }
            operator_find_sum += self.operator_finds_puppet[i];
        }

        for i in 0..self.operator_num {
            if self.operator_finds_puppet[i] > 0 {
                self.g_best[i] =
                    (self.operator_finds_puppet[i] as f64) / (operator_find_sum as f64);
            }
        }

        for swarm in 0..self.swarm_num {
            let mut probability_sum = 0.0;
            for i in 0..self.operator_num {
                self.probability_now[swarm][i] = 0.0;
                self.v_now[swarm][i] = self.w_now * self.v_now[swarm][i]
                    + self.rand_below(1000) * (self.l_best[swarm][i] - self.x_now[swarm][i])
                    + self.rand_below(1000) * (self.g_best[i] - self.x_now[swarm][i]);
                self.x_now[swarm][i] += self.v_now[swarm][i];

                if self.x_now[swarm][i] > V_MAX {
                    self.x_now[swarm][i] = V_MAX;
                } else if self.x_now[swarm][i] < V_MIN {
                    self.x_now[swarm][i] = V_MIN;
                }
                probability_sum += self.x_now[swarm][i];
            }

            for i in 0..self.operator_num {
                self.x_now[swarm][i] /= probability_sum;
                if i == 0 {
                    self.probability_now[swarm][i] = self.x_now[swarm][i];
                } else {
                    self.probability_now[swarm][i] =
                        self.probability_now[swarm][i - 1] + self.x_now[swarm][i];
                }
            }
            if self.probability_now[swarm][self.operator_num - 1] < 0.99
                || self.probability_now[swarm][self.operator_num - 1] > 1.01
            {
                return Err(Error::MOpt("Error in pso_update".to_string()));
            }
        }
        self.swarm_now = 0;

        self.key_module = MOptMode::Pilotfuzzing;
        Ok(())
    }

    /// This function is used to decide the operator that we want to apply next
    /// see <https://github.com/puppet-meteor/MOpt-AFL/blob/master/MOpt/afl-fuzz.c#L397>
    pub fn select_algorithm(&mut self) -> Result<usize, Error> {
        let mut res = 0;
        let mut sentry = 0;

        let operator_num = self.operator_num;

        // Fetch a random sele value
        let select_prob: f64 = self.probability_now[self.swarm_now][operator_num - 1]
            * (self.rand_below(10000) * 0.0001);

        for i in 0..operator_num {
            if i == 0 {
                if select_prob < self.probability_now[self.swarm_now][i] {
                    res = i;
                    break;
                }
            } else if select_prob < self.probability_now[self.swarm_now][i] {
                res = i;
                sentry = 1;
                break;
            }
        }

        if (sentry == 1 && select_prob < self.probability_now[self.swarm_now][res - 1])
            || (res + 1 < operator_num
                && select_prob > self.probability_now[self.swarm_now][res + 1])
        {
            return Err(Error::MOpt("Error in select_algorithm".to_string()));
        }

        Ok(res)
    }
}

const V_MAX: f64 = 1.0;
const V_MIN: f64 = 0.05;

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum MOptMode {
    Pilotfuzzing,
    Corefuzzing,
}

pub struct StdMOptMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R> + HasMetadata,
{
    mutations: MT,
    phantom: PhantomData<(I, R, S)>,
}

impl<I, MT, R, S> Debug for StdMOptMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R> + HasMetadata,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StdMOptMutator with {} mutations for Input type {}",
            self.mutations.len(),
            core::any::type_name::<I>()
        )
    }
}

impl<I, MT, R, S> Mutator<I, S> for StdMOptMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R> + HasMetadata,
{
    #[inline]
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input, stage_idx)
    }
}

impl<I, MT, R, S> StdMOptMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R> + HasMetadata,
{
    pub fn new(mutations: MT) -> Self {
        Self {
            mutations,
            phantom: PhantomData,
        }
    }
    fn core_mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        // TODO
        let mut r = MutationResult::Skipped;
        state
            .metadata_mut()
            .get_mut::<MOpt>()
            .unwrap()
            .update_core_operator_ctr_last();

        for _i in 0..self.iterations(state, input) {
            let idx = self.schedule(state, input);
            let outcome = self
                .mutations_mut()
                .get_and_mutate(idx, state, input, stage_idx)?;
            if outcome == MutationResult::Mutated {
                r = MutationResult::Mutated;
            }

            state
                .metadata_mut()
                .get_mut::<MOpt>()
                .unwrap()
                .core_operator_ctr_this[idx] += 1;
        }

        Ok(r)
    }

    fn pilot_mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let mut r = MutationResult::Skipped;
        let swarm_now;
        {
            let mopt = state.metadata_mut().get_mut::<MOpt>().unwrap();
            swarm_now = mopt.swarm_now;
            mopt.update_pilot_operator_ctr_last(swarm_now);
        }

        for _i in 0..self.iterations(state, input) {
            let idx = self.schedule(state, input);
            let outcome = self
                .mutations_mut()
                .get_and_mutate(idx, state, input, stage_idx)?;
            if outcome == MutationResult::Mutated {
                r = MutationResult::Mutated;
            }

            state
                .metadata_mut()
                .get_mut::<MOpt>()
                .unwrap()
                .pilot_operator_ctr_this[swarm_now][idx] += 1;
        }

        Ok(r)
    }
}

impl<I, MT, R, S> ComposedByMutations<I, MT, S> for StdMOptMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R> + HasMetadata,
{
    /// Get the mutations
    #[inline]
    fn mutations(&self) -> &MT {
        &self.mutations
    }

    // Get the mutations (mut)
    #[inline]
    fn mutations_mut(&mut self) -> &mut MT {
        &mut self.mutations
    }
}

impl<I, MT, R, S> ScheduledMutator<I, MT, S> for StdMOptMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R> + HasMetadata,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, _: &I) -> u64 {
        1 << (1 + state.rand_mut().below(6))
    }

    /// Get the next mutation to apply
    fn schedule(&self, state: &mut S, _: &I) -> usize {
        state
            .metadata_mut()
            .get_mut::<MOpt>()
            .unwrap()
            .select_algorithm()
            .unwrap()
    }

    fn scheduled_mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let mode = state.metadata().get::<MOpt>().unwrap().key_module;
        match mode {
            MOptMode::Corefuzzing => self.core_mutate(state, input, stage_idx),
            MOptMode::Pilotfuzzing => self.pilot_mutate(state, input, stage_idx),
        }
    }
}

pub trait MOptMutator<I, MT, R, S>: ScheduledMutator<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R> + HasMetadata,
{
}

impl<I, MT, R, S> MOptMutator<I, MT, R, S> for StdMOptMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R> + HasMetadata,
{
}
