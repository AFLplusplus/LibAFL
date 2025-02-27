//! The Nyx `CmpLog` Observer
//!
//! Reads and parses the redqueen results written by QEMU-Nyx and adds them to the state as `CmpValuesMetadata`.

extern crate alloc;

use alloc::borrow::Cow;

use libafl::{
    Error, HasMetadata,
    executors::ExitKind,
    observers::{CmpValues, CmpValuesMetadata, Observer},
    state::HasExecutions,
};
use libafl_bolts::Named;
pub use libafl_targets::{
    CMPLOG_MAP_H, CMPLOG_MAP_PTR, CMPLOG_MAP_SIZE, CMPLOG_MAP_W, CmpLogMap, CmpLogObserver,
    cmps::{
        __libafl_targets_cmplog_instructions, __libafl_targets_cmplog_routines, CMPLOG_ENABLED,
    },
};
use serde::{Deserialize, Serialize};

/// A [`CmpObserver`] observer for Nyx
#[derive(Serialize, Deserialize, Debug)]
pub struct NyxCmpObserver {
    /// Observer name
    name: Cow<'static, str>,
    /// Path to redqueen results file
    path: Cow<'static, str>,
    add_meta: bool,
}

impl NyxCmpObserver {
    /// Creates a new [`struct@NyxCmpObserver`] with the given filepath.
    #[must_use]
    pub fn new(name: &'static str, path: String, add_meta: bool) -> Self {
        Self {
            name: Cow::from(name),
            path: Cow::from(path),
            add_meta,
        }
    }
}

impl<I, S> Observer<I, S> for NyxCmpObserver
where
    S: HasMetadata + HasExecutions,
    I: core::fmt::Debug,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        unsafe {
            CMPLOG_ENABLED = 1;
        }
        Ok(())
    }

    fn post_exec(&mut self, state: &mut S, _input: &I, _exit_kind: &ExitKind) -> Result<(), Error> {
        unsafe {
            CMPLOG_ENABLED = 0;
        }
        if self.add_meta {
            let meta = state.metadata_or_insert_with(CmpValuesMetadata::new);
            let rq_data = parse_redqueen_data(&std::fs::read_to_string(self.path.as_ref())?);
            for event in rq_data.bps {
                if let Ok(cmp_value) = event.try_into() {
                    meta.list.push(cmp_value);
                }
            }
        }
        Ok(())
    }
}

impl Named for NyxCmpObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

// Based on https://github.com/nyx-fuzz/spec-fuzzer/blob/main/rust_fuzzer/src/runner.rs
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum RedqueenBpType {
    Str,
    Cmp,
    Sub,
}

impl RedqueenBpType {
    fn new(data: &str) -> Result<RedqueenBpType, String> {
        match data {
            "STR" => Ok(Self::Str),
            "CMP" => Ok(Self::Cmp),
            "SUB" => Ok(Self::Sub),
            _ => Err("Unknown redqueen type".to_string()),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct RedqueenEvent {
    pub addr: u64,
    pub bp_type: RedqueenBpType,
    pub size: usize,
    pub lhs: Vec<u8>,
    pub rhs: Vec<u8>,
    pub imm: bool,
}

impl RedqueenEvent {
    fn new(line: &str) -> Result<Self, String> {
        static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(
                r"([0-9a-fA-F]+)\s+(CMP|SUB|STR)\s+(\d+)\s+([0-9a-fA-F]+)-([0-9a-fA-F]+)(\sIMM)?",
            )
            .expect("Invalid regex pattern")
        });

        let captures = RE
            .captures(line)
            .ok_or_else(|| format!("Failed to parse Redqueen line: '{line}'"))?;

        let addr_s = captures.get(1).ok_or("Missing address field")?.as_str();
        let type_s = captures.get(2).ok_or("Missing type field")?.as_str();
        let size_s = captures.get(3).ok_or("Missing size field")?.as_str();
        let lhs_s = captures.get(4).ok_or("Missing LHS field")?.as_str();
        let rhs_s = captures.get(5).ok_or("Missing RHS field")?.as_str();
        let imm = captures.get(6).is_some_and(|_x| true);

        let addr =
            u64::from_str_radix(addr_s, 16).map_err(|_| format!("Invalid address: '{addr_s}'"))?;
        let bp_type = RedqueenBpType::new(type_s)
            .map_err(|e| format!("Invalid redqueen type: '{type_s}' - {e}"))?;
        let size = size_s
            .parse::<usize>()
            .map_err(|_| format!("Invalid size: '{size_s}'"))?;
        let lhs = hex_to_bytes(lhs_s).ok_or("Decoding LHS failed")?;
        let rhs = hex_to_bytes(rhs_s).ok_or("Decoding RHS failed")?;

        Ok(Self {
            addr,
            bp_type,
            size,
            lhs,
            rhs,
            imm,
        })
    }
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 == 0 {
        (0..s.len())
            .step_by(2)
            .map(|i| {
                s.get(i..i + 2)
                    .and_then(|sub| u8::from_str_radix(sub, 16).ok())
            })
            .collect()
    } else {
        None
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct RedqueenInfo {
    bps: Vec<RedqueenEvent>,
}

fn parse_redqueen_data(data: &str) -> RedqueenInfo {
    let bps = data
        .lines()
        .filter_map(|line| RedqueenEvent::new(line).ok())
        .collect::<Vec<_>>();
    RedqueenInfo { bps }
}

impl TryInto<CmpValues> for RedqueenEvent {
    type Error = String;

    fn try_into(self) -> Result<CmpValues, Self::Error> {
        match self.bp_type {
            RedqueenBpType::Cmp => match self.size {
                8 => Ok(CmpValues::U8((
                    *self.rhs.first().ok_or("Invalid RHS length for U8")?,
                    *self.lhs.first().ok_or("Invalid LHS length for U8")?,
                    self.imm,
                ))),
                16 => Ok(CmpValues::U16((
                    u16::from_be_bytes(
                        self.rhs
                            .try_into()
                            .map_err(|_| "Invalid RHS length for U16")?,
                    ),
                    u16::from_be_bytes(
                        self.lhs
                            .try_into()
                            .map_err(|_| "Invalid LHS length for U16")?,
                    ),
                    self.imm,
                ))),
                32 => Ok(CmpValues::U32((
                    u32::from_be_bytes(
                        self.rhs
                            .try_into()
                            .map_err(|_| "Invalid RHS length for U32")?,
                    ),
                    u32::from_be_bytes(
                        self.lhs
                            .try_into()
                            .map_err(|_| "Invalid LHS length for U32")?,
                    ),
                    self.imm,
                ))),
                64 => Ok(CmpValues::U64((
                    u64::from_be_bytes(
                        self.rhs
                            .try_into()
                            .map_err(|_| "Invalid RHS length for U64")?,
                    ),
                    u64::from_be_bytes(
                        self.lhs
                            .try_into()
                            .map_err(|_| "Invalid LHS length for U64")?,
                    ),
                    self.imm,
                ))),
                _ => Err("Invalid size".to_string()),
            },
            // TODO: Add encoding for `STR` and `SUB`
            _ => Err("Redqueen type not implemented".to_string()),
        }
    }
}
