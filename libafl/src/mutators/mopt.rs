//! The MOpt mutator scheduler, see https://github.com/puppet-meteor/MOpt-AFL

// MOpt global variables, currently the variable names are identical to the original MOpt implementation
// TODO: but I have to rename it when I implement the main algorithm because I don't find these names are any suggestive of their meaning
// Why there's so many puppets around..?
pub struct MOpt{
    limit_time_puppet: u64, //time to move onto pacemaker fuzzing mode
    origi_hit_cnt_puppet: u64,
    last_limit_time_start: u64,
    temp_pilot_time: u64,
    total_pacemaker_time: u64,
    total_puppet_find: u64,
    temp_puppet_find: u64,
    most_time_key: u64,
    most_time_puppet: u64,
    old_hit_count: u64,
    SPLICE_CYCLES_puppet: i32,
    limit_time_sig: i32, // if we are using MOpt or not, for LibAFL, this one is useless, I guess I'll find bunch of useless variables for LibAFL and will delete later.
    key_puppet: i32, // if we are in the pacemaker fuzzing mode?
    key_module: i32,
    w_init: f64,
    w_end: f64,
    w_now: f64,
    g_now: i32,
    g_max: i32,
    operator_num: usize, //operator_num, swarm_num, period_core are defined as macros in the original implementation, but I put it into the struct here so that we can tune these values
    swarm_num: usize,
    period_core: usize,
    tmp_core_time: u64,
    swarm_now: i32,
    x_now: Vec<Vec<f64>>,
    L_best: Vec<Vec<f64>>,
    eff_best: Vec<Vec<f64>>,
    G_best: Vec<f64>,
    v_now: Vec<Vec<f64>>,
    probability_now: Vec<Vec<f64>>,
    swarm_fitness: Vec<f64>,
    stage_finds_puppet: Vec<Vec<u64>>,
    stage_finds_puppet_v2: Vec<Vec<u64>>,
    stage_cycles_puppet: Vec<Vec<u64>>,
    stage_cycles_puppet_v2: Vec<Vec<u64>>,
    stage_cycles_puppet_v3: Vec<Vec<u64>>,
    operator_finds_puppet: Vec<u64>,
    core_operator_finds_puppet: Vec<u64>,
    core_operator_finds_puppet_v2: Vec<u64>,
    core_operator_cycles_puppet: Vec<u64>,
    core_operator_cycles_puppet_v2: Vec<u64>,
    core_operator_cycles_puppet_v3: Vec<u64>,
}

impl MOpt{
    pub fn new(&self, limit_time_puppet: u64, operator_num: usize, swarm_num: usize) -> Self{
        let limit_time_puppet2 = limit_time_puppet * 60 * 1000;
        let key_puppet = if limit_time_puppet == 0{
            1
        }
        else{
            0
        };
        Self{
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
            limit_time_sig : 1,
            key_puppet: key_puppet,
            key_module: 0,
            w_init: 0.9,
            w_end: 0.3,
            w_now: 0.0,
            g_now: 0,
            g_max: 5000,
            operator_num: operator_num,
            swarm_num: swarm_num,
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
            core_operator_cycles_puppet_v2: vec![0; operator_num],
            core_operator_cycles_puppet_v3: vec![0; operator_num],
        }
    }
}