use std::{collections::HashMap, path::PathBuf, time::Duration};

use libafl::{
    executors::forkserver::AFL_MAP_SIZE_ENV_VAR,
    stages::afl_stats::AFL_FUZZER_STATS_UPDATE_INTERVAL_SECS, Error,
};
use libafl_bolts::core_affinity::Cores;

use crate::Opt;

fn env_var_with_alias(canonical: &str, alias: &str) -> Option<String> {
    std::env::var(canonical)
        .ok()
        .or_else(|| std::env::var(alias).ok())
}

pub fn parse_envs(opt: &mut Opt) -> Result<(), Error> {
    if let Ok(res) = std::env::var("AFL_CORES") {
        opt.cores = Some(Cores::from_cmdline(&res)?);
    } else {
        return Err(Error::illegal_argument("Missing AFL_CORES"));
    }
    if let Ok(res) = std::env::var("AFL_IGNORE_UNKNOWN_ENVS") {
        opt.ignore_unknown_envs = parse_bool(&res)?;
    }
    if let Ok(res) = std::env::var("AFL_INPUT_LEN_MAX") {
        opt.max_input_len = Some(res.parse()?);
    }
    if let Ok(res) = std::env::var("AFL_INPUT_LEN_MIN") {
        opt.min_input_len = Some(res.parse()?);
    }
    if let Ok(res) = std::env::var("AFL_BENCH_JUST_ONE") {
        opt.bench_just_one = parse_bool(&res)?;
    }
    if let Ok(res) = std::env::var("AFL_BENCH_UNTIL_CRASH") {
        opt.bench_until_crash = parse_bool(&res)?;
    }
    if let Ok(res) = std::env::var("AFL_HANG_TMOUT") {
        opt.hang_timeout = res.parse()?;
    } else {
        opt.hang_timeout = 100;
    }
    if let Ok(res) = std::env::var("AFL_DEBUG_CHILD") {
        opt.debug_child = parse_bool(&res)?;
    }
    if let Ok(res) = std::env::var("AFL_PERSISTENT") {
        opt.is_persistent = parse_bool(&res)?;
    }
    if let Ok(res) = std::env::var("AFL_NO_AUTODICT") {
        opt.no_autodict = parse_bool(&res)?;
    }
    if let Ok(res) = std::env::var(AFL_MAP_SIZE_ENV_VAR) {
        let map_size = validate_map_size(res.parse()?)?;
        opt.map_size = Some(map_size);
    }
    if let Some(res) = env_var_with_alias("AFL_IGNORE_TIMEOUT", "AFL_IGNORE_TIMEOUTS") {
        opt.ignore_timeouts = parse_bool(&res)?;
    }
    if let Ok(res) = std::env::var("AFL_TMPDIR") {
        opt.cur_input_dir = Some(PathBuf::from(res));
    }
    if let Ok(res) = std::env::var("AFL_CRASH_EXITCODE") {
        opt.crash_exitcode = Some(res.parse()?);
    }
    if let Ok(res) = std::env::var("AFL_TARGET_ENV") {
        opt.target_env = parse_target_env(&res)?;
    }
    if let Ok(res) = std::env::var("AFL_CYCLE_SCHEDULES") {
        opt.cycle_schedules = parse_bool(&res)?;
    }
    if let Ok(res) = std::env::var("AFL_CMPLOG_ONLY_NEW") {
        opt.cmplog_only_new = parse_bool(&res)?;
    }
    if let Ok(res) = std::env::var("AFL_PRELOAD") {
        opt.afl_preload = Some(res);
    }
    if let Ok(res) = std::env::var("AFL_SKIP_BIN_CHECK") {
        opt.skip_bin_check = parse_bool(&res)?;
    }
    if let Ok(res) = std::env::var("AFL_AUTORESUME") {
        opt.auto_resume = parse_bool(&res)?;
    }
    if let Ok(res) = std::env::var("AFL_DEFER_FORKSRV") {
        opt.defer_forkserver = parse_bool(&res)?;
    }
    if let Ok(res) = std::env::var("AFL_FUZZER_STATS_UPDATE_INTERVAL") {
        opt.stats_interval = res.parse()?;
    } else {
        opt.stats_interval = AFL_FUZZER_STATS_UPDATE_INTERVAL_SECS;
    }
    if let Ok(res) = std::env::var("AFL_BROKER_PORT") {
        opt.broker_port = Some(res.parse()?);
    }
    if let Ok(res) = std::env::var("AFL_EXIT_ON_SEED_ISSUES") {
        opt.exit_on_seed_issues = parse_bool(&res)?;
    }
    if let Some(res) = env_var_with_alias("AFL_IGNORE_SEED_ISSUES", "AFL_IGNORE_SEED_PROBLEMS") {
        opt.ignore_seed_issues = parse_bool(&res)?;
    }
    if let Some(res) = env_var_with_alias(
        "AFL_CRASHING_SEED_AS_NEW_CRASH",
        "AFL_CRASHING_SEEDS_AS_NEW_CRASH",
    ) {
        opt.crash_seed_as_new_crash = parse_bool(&res)?;
    }
    if let Ok(res) = std::env::var("AFL_FRIDA_PERSISTENT_ADDR") {
        opt.frida_persistent_addr = Some(res);
    }
    if let Some(res) = env_var_with_alias("AFL_QEMU_CUSTOM_BIN", "AFL_CUSTOM_QEMU_BIN") {
        opt.qemu_custom_bin = parse_bool(&res)?;
    }
    if let Ok(res) = std::env::var("AFL_CS_CUSTOM_BIN") {
        opt.cs_custom_bin = parse_bool(&res)?;
    }
    if let Ok(res) = std::env::var("AFL_KILL_SIGNAL") {
        opt.kill_signal = Some(res.parse()?);
    }
    if let Ok(res) = std::env::var("AFL_PERSISTENT_RECORD") {
        opt.persistent_record = res.parse()?;
    }
    if let Ok(res) = std::env::var("AFL_SYNC_TIME") {
        opt.foreign_sync_interval = Duration::from_secs(res.parse::<u64>()? * 60);
    } else {
        opt.foreign_sync_interval = Duration::from_secs(AFL_DEFAULT_FOREIGN_SYNC_INTERVAL);
    }
    if let Ok(res) = std::env::var("AFL_USE_FASAN") {
        opt.frida_asan = parse_bool(&res)?;
    }
    if let Ok(res) = std::env::var("AFL_NO_UI") {
        opt.no_ui = parse_bool(&res)?;
    }
    if let Ok(res) = std::env::var("AFL_PIZZA_MODE") {
        opt.pizza_mode = parse_bool(&res)?;
    }
    if let Ok(res) = std::env::var("AFL_EXIT_WHEN_DONE") {
        opt.exit_when_done = parse_bool(&res)?;
    }
    if let Ok(res) = std::env::var("AFL_FINAL_SYNC") {
        opt.final_sync = parse_bool(&res)?;
    }
    warn_on_unknown_afl_envs(opt.ignore_unknown_envs);
    Ok(())
}

fn warn_on_unknown_afl_envs(ignore_unknown_envs: bool) {
    const KNOWN_AFL_ENVS: &[&str] = &[
        "AFL_AUTORESUME",
        "AFL_BENCH_JUST_ONE",
        "AFL_BENCH_UNTIL_CRASH",
        "AFL_BROKER_PORT",
        "AFL_CORES",
        "AFL_CMPLOG_ONLY_NEW",
        "AFL_CRASHING_SEED_AS_NEW_CRASH",
        "AFL_CRASHING_SEEDS_AS_NEW_CRASH",
        "AFL_CRASH_EXITCODE",
        "AFL_CS_CUSTOM_BIN",
        "AFL_CYCLE_SCHEDULES",
        "AFL_CUSTOM_QEMU_BIN",
        "AFL_DEBUG_CHILD",
        "AFL_DEFER_FORKSRV",
        "AFL_EXIT_ON_SEED_ISSUES",
        "AFL_EXIT_WHEN_DONE",
        "AFL_FINAL_SYNC",
        "AFL_FRIDA_PERSISTENT_ADDR",
        "AFL_FUZZER_STATS_UPDATE_INTERVAL",
        "AFL_HANG_TMOUT",
        "AFL_IGNORE_SEED_ISSUES",
        "AFL_IGNORE_SEED_PROBLEMS",
        "AFL_IGNORE_TIMEOUT",
        "AFL_IGNORE_TIMEOUTS",
        "AFL_IGNORE_UNKNOWN_ENVS",
        "AFL_INPUT_LEN_MAX",
        "AFL_INPUT_LEN_MIN",
        "AFL_KILL_SIGNAL",
        "AFL_MAP_SIZE",
        "AFL_NO_AUTODICT",
        "AFL_NO_UI",
        "AFL_PERSISTENT",
        "AFL_PERSISTENT_RECORD",
        "AFL_PIZZA_MODE",
        "AFL_PRELOAD",
        "AFL_QEMU_CUSTOM_BIN",
        "AFL_SKIP_BIN_CHECK",
        "AFL_SYNC_TIME",
        "AFL_TARGET_ENV",
        "AFL_TMPDIR",
        "AFL_USE_FASAN",
    ];

    if ignore_unknown_envs {
        return;
    }

    for (key, _) in std::env::vars() {
        if key.starts_with("AFL_") && !KNOWN_AFL_ENVS.contains(&key.as_str()) {
            eprintln!(
                "warning: Unknown AFL environment variable '{key}'. Set AFL_IGNORE_UNKNOWN_ENVS=1 to suppress this warning."
            );
        }
    }
}

fn parse_bool(val: &str) -> Result<bool, Error> {
    match val {
        "1" => Ok(true),
        "0" => Ok(false),
        _ => Err(Error::illegal_argument(
            "boolean values must be either 1 for true or 0 for false",
        )),
    }
}

/// parse `AFL_TARGET_ENV`; expects: FOO=BAR TEST=ASD
fn parse_target_env(s: &str) -> Result<Option<HashMap<String, String>>, Error> {
    let env_regex = regex::Regex::new(r"([^\s=]+)\s*=\s*([^\s]+)").unwrap();
    let mut target_env = HashMap::new();
    for vars in env_regex.captures_iter(s) {
        _ = target_env.insert(
            vars.get(1)
                .ok_or_else(|| Error::illegal_argument("invalid AFL_TARGET_ENV format"))?
                .as_str()
                .to_string(),
            vars.get(2)
                .ok_or_else(|| Error::illegal_argument("invalid AFL_TARGET_ENV format"))?
                .as_str()
                .to_string(),
        );
    }
    Ok(Some(target_env))
}

fn validate_map_size(map_size: usize) -> Result<usize, Error> {
    if map_size > AFL_MAP_SIZE_MIN && map_size < AFL_MAP_SIZE_MAX {
        Ok(map_size)
    } else {
        Err(Error::illegal_argument(format!(
            "AFL_MAP_SIZE not in range {AFL_MAP_SIZE_MIN} (2 ^ 3) - {AFL_MAP_SIZE_MAX} (2 ^ 30)",
        )))
    }
}

const AFL_MAP_SIZE_MIN: usize = usize::pow(2, 3);
const AFL_MAP_SIZE_MAX: usize = usize::pow(2, 30);
const AFL_DEFAULT_FOREIGN_SYNC_INTERVAL: u64 = 20 * 60;
pub const AFL_DEFAULT_MAP_SIZE: usize = 65536;
