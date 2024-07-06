use std::borrow::Cow;

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
