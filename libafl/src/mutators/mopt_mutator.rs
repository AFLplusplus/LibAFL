//! The `MOpt` mutator scheduler, see <https://github.com/puppet-meteor/MOpt-AFL>

// MOpt global variables, currently the variable names are identical to the original MOpt implementation
// TODO: but I have to rename it when I implement the main algorithm because I don't find these names are any suggestive of their meaning
// Why there's so many puppets around..?

use alloc::{string::ToString, vec::Vec};

use crate::{
    bolts::{current_time, rands::Rand, rands::StdRand},
    inputs::Input,
    mutators::{ComposedByMutations, MutationResult, Mutator, MutatorsTuple, ScheduledMutator},
    state::{HasMOpt, HasRand},
    Error,
};
use core::{
    fmt::{self, Debug},
    marker::PhantomData,
    time::Duration,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MOpt {
    pub rand: StdRand,
    pub finds_until_core_begin: usize, // How many findings have we found since we switched to the current mode?
    pub last_limit_time_start: Duration, // Unneeded variable
    pub total_finds: usize,
    pub finds_until_pilot_begin: usize,
    pub most_time_key: u64, // This is a flag to indicate if we'll stop fuzzing after 'most_time_puppet', these are unneeded for LibAFL
    pub most_time_puppet: u64, // Unneeded for LibAFL
    pub SPLICE_CYCLES_puppet: i32,
    pub limit_time_sig: i32, // If we are using MOpt or not, for LibAFL, this one is useless, I guess I'll find bunch of useless variables for LibAFL and will delete later.
    pub key_module: MOptMode, // Pilot_fuzzing(0) or core_fuzzing(1) or pso_updating(2)
    pub w_init: f64, // These w_* and g_* are the coefficients for updating the positions and the velocities for PSO algorithm.
    pub w_end: f64,  // w_* means inertia
    pub w_now: f64,
    pub g_now: i32,
    pub g_max: i32,
    pub operator_num: usize, // Operator_num, swarm_num, period_core are defined as macros in the original implementation, but I put it into the struct here so that we can tune these values
    pub swarm_num: usize,    // Number of swarms
    pub period_pilot: usize, // We'll generate test for period_pilot times before we call pso_update in core fuzzing module, as stated in the original thesis 4.1.2
    pub period_core: usize, // We'll generate test for period_core times before we call pso_update in core fuzzing module, as stated in the original thesis 4.1.3
    pub pilot_time: usize,  // The number of testcase generated using pilot fzzing module so far
    pub core_time: usize,   // The number of testcase generated using core fuzzing module so far
    pub swarm_now: usize,   // Current swarm
    x_now: Vec<Vec<f64>>, // The positions of PSO algo
    L_best: Vec<Vec<f64>>, // The local optimum
    eff_best: Vec<Vec<f64>>,
    G_best: Vec<f64>,     // The global optimum
    v_now: Vec<Vec<f64>>, // The speed
    probability_now: Vec<Vec<f64>>,
    pub swarm_fitness: Vec<f64>, // The fitness value for each swarm, we want to see which swarm is the *best* in core fuzzing module
    pub pilot_operator_finds_pso: Vec<Vec<usize>>,
    pub pilot_operator_finds_per_stage: Vec<Vec<usize>>,
    pub pilot_operator_ctr_pso: Vec<Vec<usize>>,
    pub pilot_operator_ctr_per_stage: Vec<Vec<usize>>,
    pub pilot_operator_ctr_last: Vec<Vec<usize>>,
    pub operator_finds_puppet: Vec<usize>,
    pub core_operator_finds_pso: Vec<usize>,
    pub core_operator_finds_per_stage: Vec<usize>,
    pub core_operator_ctr_pso: Vec<usize>,
    pub core_operator_ctr_per_stage: Vec<usize>,
    pub core_operator_ctr_last: Vec<usize>,
}

crate::impl_serdeany!(MOpt);

impl MOpt {
    pub fn new(operator_num: usize, swarm_num: usize) -> Self {
        Self {
            rand: StdRand::with_seed(0),
            finds_until_core_begin: 0,
            last_limit_time_start: Duration::from_millis(0),
            total_finds: 0,
            finds_until_pilot_begin: 0,
            most_time_key: 0,
            most_time_puppet: 0,
            SPLICE_CYCLES_puppet: 0,
            limit_time_sig: 1,
            key_module: MOptMode::CORE_FUZZING,
            w_init: 0.9,
            w_end: 0.3,
            w_now: 0.0,
            g_now: 0,
            g_max: 5000,
            operator_num: operator_num,
            swarm_num: swarm_num,
            period_pilot: 50000,
            period_core: 500000,
            pilot_time: 0,
            core_time: 0,
            swarm_now: 0,
            x_now: vec![vec![0.0; operator_num]; swarm_num],
            L_best: vec![vec![0.0; operator_num]; swarm_num],
            eff_best: vec![vec![0.0; operator_num]; swarm_num],
            G_best: vec![0.0; operator_num],
            v_now: vec![vec![0.0; operator_num]; swarm_num],
            probability_now: vec![vec![0.0; operator_num]; swarm_num],
            swarm_fitness: vec![0.0; swarm_num],
            pilot_operator_finds_pso: vec![vec![0; operator_num]; swarm_num],
            pilot_operator_finds_per_stage: vec![vec![0; operator_num]; swarm_num],
            pilot_operator_ctr_pso: vec![vec![0; operator_num]; swarm_num],
            pilot_operator_ctr_per_stage: vec![vec![0; operator_num]; swarm_num],
            pilot_operator_ctr_last: vec![vec![0; operator_num]; swarm_num],
            operator_finds_puppet: vec![0; operator_num],
            core_operator_finds_pso: vec![0; operator_num],
            core_operator_finds_per_stage: vec![0; operator_num],
            core_operator_ctr_pso: vec![0; operator_num],
            core_operator_ctr_per_stage: vec![0; operator_num],
            core_operator_ctr_last: vec![0; operator_num],
        }
    }

    /// Get a float below the given `size` value times `0.001`.
    /// So `size` 100 will result in anything between `0` and 0.1`.
    #[inline]
    #[allow(clippy::cast_precision_loss)]
    pub fn rand_below(&mut self, size: u64) -> f64
where {
        self.rand.below(size) as f64 * 0.001
    }

    pub fn init_core_module(&mut self) -> Result<(), Error> {
        // Initialize core_operator_* values
        for i in 0..self.operator_num {
            self.core_operator_ctr_per_stage[i] = self.core_operator_ctr_pso[i];
            self.core_operator_ctr_last[i] = self.core_operator_ctr_pso[i];
            self.core_operator_finds_per_stage[i] = self.core_operator_finds_pso[i]
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
            self.pilot_operator_ctr_last[swarm_now][i] =
                self.pilot_operator_ctr_per_stage[swarm_now][i]
        }
    }

    #[inline]
    pub fn update_core_operator_ctr_last(&mut self) {
        for i in 0..self.operator_num {
            self.core_operator_ctr_last[i] = self.core_operator_ctr_per_stage[i];
        }
    }

    #[allow(clippy::cast_precision_loss)]
    pub fn update_pilot_operator_ctr_pso(&mut self, swarm_now: usize) {
        let mut eff = 0.0;
        for i in 0..self.operator_num {
            if self.pilot_operator_ctr_per_stage[swarm_now][i]
                > self.pilot_operator_ctr_pso[swarm_now][i]
            {
                eff = ((self.pilot_operator_finds_per_stage[swarm_now][i]
                    - self.pilot_operator_finds_pso[swarm_now][i]) as f64)
                    / ((self.pilot_operator_ctr_per_stage[swarm_now][i]
                        - self.pilot_operator_ctr_pso[swarm_now][i]) as f64)
            }

            if self.eff_best[swarm_now][i] < eff {
                self.eff_best[swarm_now][i] = eff;
                self.L_best[swarm_now][i] = self.x_now[swarm_now][i];
            }

            self.pilot_operator_finds_pso[swarm_now][i] =
                self.pilot_operator_finds_per_stage[swarm_now][i];
            self.pilot_operator_ctr_pso[swarm_now][i] =
                self.pilot_operator_ctr_per_stage[swarm_now][i];
        }
    }

    #[inline]
    pub fn update_core_operator_ctr_pso(&mut self) {
        for i in 0..self.operator_num {
            self.core_operator_finds_pso[i] = self.core_operator_finds_per_stage[i];
            self.core_operator_ctr_pso[i] = self.core_operator_ctr_per_stage[i];
        }
    }

    #[inline]
    pub fn set_last_limit_time_start(&mut self) {
        self.last_limit_time_start = current_time();
    }


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
                self.G_best[i] =
                    (self.operator_finds_puppet[i] as f64) / (operator_find_sum as f64);
            }
        }

        for swarm in 0..self.swarm_num {
            let mut probability_sum = 0.0;
            for i in 0..self.operator_num {
                self.probability_now[swarm][i] = 0.0;
                self.v_now[swarm][i] = self.w_now * self.v_now[swarm][i]
                    + self.rand_below(1000) * (self.L_best[swarm][i] - self.x_now[swarm][i])
                    + self.rand_below(1000) * (self.G_best[i] - self.x_now[swarm][i]);
                self.x_now[swarm][i] += self.v_now[swarm][i];

                if self.x_now[swarm][i] > V_MAX {
                    self.x_now[swarm][i] = V_MAX;
                } else if self.x_now[swarm][i] < V_MIN {
                    self.x_now[swarm][i] = V_MIN;
                }
                probability_sum += self.x_now[swarm][i];
            }

            for i in 0..self.operator_num {
                self.x_now[swarm][i] = self.x_now[swarm][i] / probability_sum;
                if i != 0 {
                    self.probability_now[swarm][i] =
                        self.probability_now[swarm][i - 1] + self.x_now[swarm][i];
                } else {
                    self.probability_now[swarm][i] = self.x_now[swarm][i];
                }
            }
            if self.probability_now[swarm][self.operator_num - 1] < 0.99
                || self.probability_now[swarm][self.operator_num - 1] > 1.01
            {
                return Err(Error::MOpt("Error in pso_update".to_string()));
            }
        }
        self.swarm_now = 0;

        self.key_module = MOptMode::PILOT_FUZZING;
        Ok(())
    }

    // The function select_algorithm() from https://github.com/puppet-meteor/MOpt-AFL/blob/master/MOpt/afl-fuzz.c#L397, it's more of select_mutator for libAFL
    pub fn select_algorithm(&mut self) -> Result<usize, Error> {
        let mut res = 0;
        let mut sentry = 0;

        let operator_num = self.operator_num;

        // Fetch a random sele value
        let sele: f64 = self.probability_now[self.swarm_now][operator_num - 1]
            * (self.rand_below(10000) * 0.0001);

        for i in 0..operator_num {
            if i == 0 {
                if sele < self.probability_now[self.swarm_now][i] {
                    res = i;
                    break;
                }
            } else {
                if sele < self.probability_now[self.swarm_now][i] {
                    res = i;
                    sentry = 1;
                    break;
                }
            }
        }

        if (sentry == 1 && sele < self.probability_now[self.swarm_now][res - 1])
            || (res + 1 < operator_num && sele > self.probability_now[self.swarm_now][res + 1])
        {
            return Err(Error::MOpt("Error in select_algorithm".to_string()));
        }

        Ok(res)
    }
}

const V_MAX: f64 = 1.0;
const V_MIN: f64 = 0.05;

const SPLICE_CYCLES_puppet_up: usize = 25;
const SPLICE_CYCLES_puppet_low: usize = 5;
const STAGE_RANDOMBYTE: usize = 12;
const STAGE_DELETEBYTE: usize = 13;
const STAGE_Clone75: usize = 14;
const STAGE_OverWrite75: usize = 15;
const STAGE_OverWriteExtra: usize = 16;
const STAGE_InsertExtra: usize = 17;

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum MOptMode {
    PILOT_FUZZING,
    CORE_FUZZING,
}

pub struct StdMOptMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R> + HasMOpt,
{
    mutations: MT,
    phantom: PhantomData<(I, R, S)>,
}

impl<I, MT, R, S> Debug for StdMOptMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R> + HasMOpt,
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
    S: HasRand<R> + HasMOpt,
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
    S: HasRand<R> + HasMOpt,
{
    pub fn new(mutations: MT) -> Self {
        Self {
            mutations: mutations,
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
        state.mopt_mut().update_core_operator_ctr_last();
        for _i in 0..self.iterations(state, input) {
            let idx = self.schedule(state, input);
            let outcome = self
                .mutations_mut()
                .get_and_mutate(idx, state, input, stage_idx)?;
            if outcome == MutationResult::Mutated {
                r = MutationResult::Mutated;
            }
            state
                .mopt_mut()
                .core_operator_ctr_per_stage[idx] += 1;
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
        let swarm_now = state.mopt().swarm_now;
        state.mopt_mut().update_pilot_operator_ctr_last(swarm_now);

        for _i in 0..self.iterations(state, input) {
            let idx = self.schedule(state, input);
            let outcome = self
                .mutations_mut()
                .get_and_mutate(idx, state, input, stage_idx)?;
            if outcome == MutationResult::Mutated {
                r = MutationResult::Mutated;
            }
            state
                .mopt_mut()
                .pilot_operator_ctr_per_stage[swarm_now][idx] += 1;
        }

        Ok(r)
    }
}

impl<I, MT, R, S> ComposedByMutations<I, MT, S> for StdMOptMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R> + HasMOpt,
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
    S: HasRand<R> + HasMOpt,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, _: &I) -> u64 {
        1 << (1 + state.rand_mut().below(6))
    }

    /// Get the next mutation to apply
    fn schedule(&self, state: &mut S, _: &I) -> usize {
        state.mopt_mut().select_algorithm().unwrap()
    }

    fn scheduled_mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let mode = state.mopt().key_module;
        let result = match mode {
            MOptMode::CORE_FUZZING => self.core_mutate(state, input, stage_idx),
            MOptMode::PILOT_FUZZING => self.pilot_mutate(state, input, stage_idx),
        };

        result
    }
}

pub trait MOptMutator<I, MT, R, S>: ScheduledMutator<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R> + HasMOpt,
{
}

impl<I, MT, R, S> MOptMutator<I, MT, R, S> for StdMOptMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R> + HasMOpt,
{
}
