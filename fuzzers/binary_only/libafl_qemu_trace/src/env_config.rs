use core::fmt;
use std::{ops::Range, str::FromStr, sync::LazyLock};

use libafl_qemu::GuestAddr;

macro_rules! def_env {
    (
        $(#[$meta:meta])*
        $env_name:ident, $env_ty:ty, $converter_func:path
    ) => {
        $(#[$meta])*
        pub static $env_name: std::sync::LazyLock<Option<$env_ty>> = LazyLock::new(|| {
            let res = std::env::var(stringify!($env_name));

            match res {
                Ok(val) => Some($converter_func(val.to_string()).unwrap()),
                Err(std::env::VarError::NotPresent) => None,
                _ => panic!("Error while fetching env variable: {res:?}"),
            }
        });
    }
}

fn env_bool(s: String) -> Result<bool, String> {
    match s.as_str() {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(format!("Couldn't convert {s} into a boolean.")),
    }
}

fn env_ranges<T>(s: String) -> Result<Vec<Range<T>>, String>
where
    T: FromStr,
    <T as FromStr>::Err: fmt::Display,
{
    let ranges_to_parse = s.split(",");

    let mut ranges: Vec<Range<T>> = Vec::new();

    for range_str in ranges_to_parse {
        let mut range_bounds = range_str.split("-");

        if range_bounds.clone().count() != 2 {
            return Err(format!("Invalid range syntax: {range_str}"));
        }

        let start_addr = range_bounds
            .next()
            .unwrap()
            .parse::<T>()
            .map_err(|e| format!("Couldn't parse range start address: {e}"))?;

        let end_addr = range_bounds
            .next()
            .unwrap()
            .parse::<T>()
            .map_err(|e| format!("Couldn't parse range end address: {e}"))?;

        ranges.push(start_addr..end_addr);
    }

    Ok(ranges)
}

fn env_val<T>(s: String) -> Result<T, String>
where
    T: FromStr,
    <T as FromStr>::Err: fmt::Display,
{
    s.parse::<T>().map_err(|e| e.to_string())
}

macro_rules! def_env_bool {
    (
        $(#[$meta:meta])*
        $env_name:ident
    ) => {
        $(#[$meta])*
        def_env!($env_name, bool, env_bool);
    }
}

macro_rules! def_env_u32 {
    (
        $(#[$meta:meta])*
        $env_name:ident
    ) => {
        $(#[$meta])*
        def_env!($env_name, u32, env_val::<u32>);
    }
}

macro_rules! def_env_addr {
    (
        $(#[$meta:meta])*
        $env_name:ident
    ) => {
        $(#[$meta])*
        def_env!($env_name, GuestAddr, env_val::<GuestAddr>);
    }
}

macro_rules! def_env_addr_ranges {
    (
        $(#[$meta:meta])*
        $env_name:ident
    ) => {
        $(#[$meta])*
        def_env!($env_name, Vec<Range<GuestAddr>>, env_ranges::<GuestAddr>);
    }
}

def_env_addr!(AFL_ENTRYPOINT);
def_env_u32!(AFL_INST_RATIO);
def_env_u32!(__AFL_SHM_ID);
def_env_u32!(__AFL_SHM_FUZZ_ID);

/// CmpLog map SHM ID
def_env_u32!(__AFL_CMPLOG_SHM_ID);

/// Asan SHM ID
def_env_u32!(__AFL_ASAN_SHM_ID);

/// Disable TB caching
def_env_bool!(AFL_QEMU_DISABLE_CACHE);

/// Enable cmplog forkserver
def_env_bool!(___AFL_EINS_ZWEI_POLIZEI___);

def_env_bool!(AFL_INST_LIBS);

/// Set code start vaddr manually
def_env_addr!(AFL_CODE_START);

/// Set code end vaddr manually
def_env_addr!(AFL_CODE_END);

/// Set instrumentation ranges
///
/// Format:
/// 0xaaaa-0xbbbb,0xcccc-0xdddd
def_env_addr_ranges!(AFL_QEMU_INST_RANGES);

/// Exclude instrumentation ranges
///
/// Format is same as [`AFL_QEMU_INST_RANGES`]
def_env_addr_ranges!(AFL_QEMU_EXCLUDE_RANGES);

/// Enable debugging
def_env_bool!(AFL_DEBUG);

def_env_bool!(AFL_QEMU_COMPCOV);

def_env_u32!(AFL_COMPCOV_LEVEL);

def_env_bool!(AFL_QEMU_FORCE_DFL);

def_env_addr!(AFL_QEMU_PERSISTENT_ADDR);

def_env_addr!(AFL_QEMU_PERSISTENT_RET);

def_env_bool!(AFL_QEMU_PERSISTENT_HOOK);

def_env_bool!(AFL_QEMU_PERSISTENT_MEM);

def_env_bool!(AFL_QEMU_PERSISTENT_GPR);

def_env_u32!(AFL_QEMU_PERSISTENT_CNT);

def_env_bool!(AFL_QEMU_PERSISTENT_EXITS);

def_env_bool!(AFL_QEMU_SNAPSHOT);

def_env_addr!(AFL_QEMU_PERSISTENT_RETADDR_OFFSET);

def_env_bool!(AFL_USE_QASAN);

def_env_bool!(AFL_NO_CRASH_README);
