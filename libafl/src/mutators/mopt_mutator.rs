//! The `MOpt` mutator scheduler, see <https://github.com/puppet-meteor/MOpt-AFL>

// MOpt global variables, currently the variable names are identical to the original MOpt implementation
// TODO: but I have to rename it when I implement the main algorithm because I don't find these names are any suggestive of their meaning
// Why there's so many puppets around..?

use alloc::{string::ToString, vec::Vec};

use crate::{
    bolts::rands::Rand,
    inputs::Input,
    mutators::{ComposedByMutations, MutationResult, Mutator, MutatorsTuple, ScheduledMutator},
    state::{HasMOpt, HasRand},
    Error,
};
use core::{
    fmt::{self, Debug},
    marker::PhantomData,
};

#[derive(Clone, Debug)]
pub struct MOpt<I, R>
where
    I: Input,
    R: Rand,
{
    rand: R,
    limit_time_puppet: u64, // Time before we move onto pacemaker fuzzing mode
    origi_hit_cnt_puppet: u64,
    last_limit_time_start: u64, // Unneeded variable
    total_pacemaker_time: u64,  // Simply tmp_core_time + tmp_pilot_time
    total_puppet_find: u64,
    temp_puppet_find: u64,
    most_time_key: u64, // This is a flag to indicate if we'll stop fuzzing after 'most_time_puppet', these are unneeded for LibAFL
    most_time_puppet: u64, // Unneeded for LibAFL
    old_hit_count: u64, // Unneeded variable
    SPLICE_CYCLES_puppet: i32,
    limit_time_sig: i32, // If we are using MOpt or not, for LibAFL, this one is useless, I guess I'll find bunch of useless variables for LibAFL and will delete later.
    key_puppet: i32,     // If we are in the pacemaker fuzzing mode?
    key_module: MOptMode, // Pilot_fuzzing(0) or core_fuzzing(1) or pso_updating(2)
    w_init: f64, // These w_* and g_* are the coefficients for updating the positions and the velocities for PSO algorithm.
    w_end: f64,  // w_* means inertia
    w_now: f64,
    g_now: i32,
    g_max: i32,
    operator_num: usize, // Operator_num, swarm_num, period_core are defined as macros in the original implementation, but I put it into the struct here so that we can tune these values
    swarm_num: usize,    // Number of swarms
    period_pilot: usize, // We'll generate test for period_pilot times before we call pso_update in core fuzzing module, as stated in the original thesis 4.1.2
    period_core: usize, // We'll generate test for period_core times before we call pso_update in core fuzzing module, as stated in the original thesis 4.1.3
    temp_pilot_time: u64, // The number of testcase generated using pilot fzzing module so far
    tmp_core_time: u64, // The number of testcase generated using core fuzzing module so far
    swarm_now: usize,   // Current swarm
    x_now: Vec<Vec<f64>>, // The positions of PSO algo
    L_best: Vec<Vec<f64>>, // The local optimum
    eff_best: Vec<Vec<f64>>,
    G_best: Vec<f64>,     // The global optimum
    v_now: Vec<Vec<f64>>, // The speed
    probability_now: Vec<Vec<f64>>,
    swarm_fitness: Vec<f64>, // The fitness value for each swarm, we want to see which swarm is the *best* in core fuzzing module
    stage_finds_puppet: Vec<Vec<u64>>,
    stage_finds_puppet_v2: Vec<Vec<u64>>,
    stage_cycles_puppet: Vec<Vec<u64>>,
    stage_cycles_puppet_v2: Vec<Vec<u64>>,
    stage_cycles_puppet_v3: Vec<Vec<u64>>,
    operator_finds_puppet: Vec<u64>,
    core_operator_finds_puppet: Vec<u64>,
    core_operator_finds_puppet_v2: Vec<u64>,
    core_operator_cycles_puppet: Vec<u64>,
    core_operator_ctr: Vec<u64>,
    core_operator_ctr_sum: Vec<u64>,
    phantom: PhantomData<I>,
}

impl<I, R> MOpt<I, R>
where
    I: Input,
    R: Rand,
{
    pub fn new(limit_time_puppet: u64, rand: R, operator_num: usize, swarm_num: usize) -> Self {
        let limit_time_puppet2 = limit_time_puppet * 60 * 1000;
        let key_puppet = if limit_time_puppet == 0 { 1 } else { 0 };
        Self {
            rand: rand,
            limit_time_puppet: 0,
            origi_hit_cnt_puppet: 0,
            last_limit_time_start: 0,
            temp_pilot_time: 0,
            total_pacemaker_time: 0,
            total_puppet_find: 0,
            temp_puppet_find: 0,
            most_time_key: 0,
            most_time_puppet: 0,
            old_hit_count: 0,
            SPLICE_CYCLES_puppet: 0,
            limit_time_sig: 1,
            key_puppet: key_puppet,
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
            tmp_core_time: 0,
            swarm_now: 0,
            x_now: vec![vec![0.0; operator_num]; swarm_num],
            L_best: vec![vec![0.0; operator_num]; swarm_num],
            eff_best: vec![vec![0.0; operator_num]; swarm_num],
            G_best: vec![0.0; operator_num],
            v_now: vec![vec![0.0; operator_num]; swarm_num],
            probability_now: vec![vec![0.0; operator_num]; swarm_num],
            swarm_fitness: vec![0.0; swarm_num],
            stage_finds_puppet: vec![vec![0; operator_num]; swarm_num],
            stage_finds_puppet_v2: vec![vec![0; operator_num]; swarm_num],
            stage_cycles_puppet: vec![vec![0; operator_num]; swarm_num],
            stage_cycles_puppet_v2: vec![vec![0; operator_num]; swarm_num],
            stage_cycles_puppet_v3: vec![vec![0; operator_num]; swarm_num],
            operator_finds_puppet: vec![0; operator_num],
            core_operator_finds_puppet: vec![0; operator_num],
            core_operator_finds_puppet_v2: vec![0; operator_num],
            core_operator_cycles_puppet: vec![0; operator_num],
            core_operator_ctr: vec![0; operator_num],
            core_operator_ctr_sum: vec![0; operator_num],
            phantom: PhantomData,
        }
    }

    /// Get a float below the given `size` value times `0.001`.
    /// So `size` 100 will result in anything between `0` and 0.1`.
    #[inline]
    #[allow(clippy::cast_precision_loss)]
    pub fn rand_below(&mut self, size: u64) -> f64 {
        self.rand.below(size) as f64 * 0.001
    }

    #[inline]
    pub fn key_module(&self) -> MOptMode {
        self.key_module
    }

    #[inline]
    pub fn core_update_operator_ctr(&mut self) {
        for i in 0..self.operator_num {
            self.core_operator_ctr_sum[i] = self.core_operator_ctr[i];
        }
    }

    #[inline]
    pub fn core_inc_operator_ctr(&mut self, idx: usize) {
        self.core_operator_ctr[idx] += 1;
    }

    #[inline]
    pub fn operator_num(&self) -> usize {
        self.operator_num
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
            self.operator_finds_puppet[i] = self.core_operator_cycles_puppet[i];

            for j in 0..self.swarm_num {
                self.operator_finds_puppet[i] += self.stage_finds_puppet[j][i];
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

                if self.x_now[swarm][i] > v_max {
                    self.x_now[swarm][i] = v_max;
                } else if self.x_now[swarm][i] < v_min {
                    self.x_now[swarm][i] = v_min;
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
        // self.key_module = 0;
        Ok(())
    }

    // The function select_algorithm() from https://github.com/puppet-meteor/MOpt-AFL/blob/master/MOpt/afl-fuzz.c#L397, it's more of select_mutator for libAFL
    pub fn select_algorithm(&mut self) -> Result<usize, Error> {
        let mut res = 0;
        let mut sentry = 0;

        /*
        // extras are for dictionaries, we don't need this piece of code for now
        let operator_num = if extras < 2 {
            self.operator_num - 2
        } else {
            self.operator_num
        };
        */
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

const v_max: f64 = 1.0;
const v_min: f64 = 0.05;
const limit_time_bound: f64 = 1.1;
const SPLICE_CYCLES_puppet_up: usize = 25;
const SPLICE_CYCLES_puppet_low: usize = 5;
const STAGE_RANDOMBYTE: usize = 12;
const STAGE_DELETEBYTE: usize = 13;
const STAGE_Clone75: usize = 14;
const STAGE_OverWrite75: usize = 15;
const STAGE_OverWriteExtra: usize = 16;
const STAGE_InsertExtra: usize = 17;
const period_pilot_tmp: f64 = 5000.0;

#[derive(Clone, Copy, Debug)]
pub enum MOptMode {
    PILOT_FUZZING,
    CORE_FUZZING,
}

pub struct MOptMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R> + HasMOpt<I, R>,
{
    mutations: MT,
    phantom: PhantomData<(I, R, S)>,
}

impl<I, MT, R, S> Debug for MOptMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R> + HasMOpt<I, R>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MOptMutator with {} mutations for Input type {}",
            self.mutations.len(),
            core::any::type_name::<I>()
        )
    }
}

impl<I, MT, R, S> Mutator<I, S> for MOptMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R> + HasMOpt<I, R>,
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

impl<I, MT, R, S> MOptMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R> + HasMOpt<I, R>,
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
        let mut r = MutationResult::Mutated;
        state.mopt_mut().core_update_operator_ctr();
        for i in 0..self.iterations(state, input) {
            let idx = self.schedule(state, input);
            let outcome = self
                .mutations_mut()
                .get_and_mutate(idx, state, input, stage_idx)?;
            if outcome != MutationResult::Mutated {
                r = MutationResult::Skipped;
            }
            state.mopt_mut().core_inc_operator_ctr(idx);
        }

        Ok(r)
    }

    fn pilot_mutate(
        &mut self,
        _state: &mut S,
        _input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        // TODO
        Ok(MutationResult::Mutated)
    }
}

impl<I, MT, R, S> ComposedByMutations<I, MT, S> for MOptMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R> + HasMOpt<I, R>,
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

impl<I, MT, R, S> ScheduledMutator<I, MT, S> for MOptMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R> + HasMOpt<I, R>,
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
        let mode = state.mopt().key_module();
        let result = match mode {
            MOptMode::CORE_FUZZING => self.core_mutate(state, input, stage_idx),
            MOptMode::PILOT_FUZZING => self.pilot_mutate(state, input, stage_idx),
        };

        result
    }
}
