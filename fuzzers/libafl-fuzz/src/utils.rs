use std::borrow::Cow;

use libafl::schedulers::powersched::PowerSchedule;

/// The power schedule to use; Copied so we can use `clap::ValueEnum`
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerScheduleCustom {
    /// The `explore` power schedule
    Explore,
    /// The `exploit` power schedule
    Exploit,
    /// The `fast` power schedule
    Fast,
    /// The `coe` power schedule
    Coe,
    /// The `lin` power schedule
    Lin,
    /// The `quad` power schedule
    Quad,
}

impl From<PowerScheduleCustom> for PowerSchedule {
    fn from(val: PowerScheduleCustom) -> Self {
        match val {
            PowerScheduleCustom::Explore => PowerSchedule::EXPLORE,
            PowerScheduleCustom::Coe => PowerSchedule::COE,
            PowerScheduleCustom::Lin => PowerSchedule::LIN,
            PowerScheduleCustom::Fast => PowerSchedule::FAST,
            PowerScheduleCustom::Quad => PowerSchedule::QUAD,
            PowerScheduleCustom::Exploit => PowerSchedule::EXPLOIT,
        }
    }
}
#[macro_export]
macro_rules! run_fuzzer_with_stage {
    ($opt: expr, $fuzzer: expr, $stages:expr, $executor: expr, $state: expr, $mgr: expr) => {
        if $opt.bench_just_one {
            $fuzzer.fuzz_loop_for($stages, $executor, $state, $mgr, 1)?;
        } else {
            $fuzzer.fuzz_loop($stages, $executor, $state, $mgr)?;
        }
    };
}

/// Get the command used to invoke libafl-fuzz
pub fn get_run_cmdline() -> Cow<'static, str> {
    let args: Vec<String> = std::env::args().collect();
    Cow::Owned(args.join(" "))
}
