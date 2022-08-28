//! Structs which are used to interact with the Inspector API
//!
//! Source is unmodified from original. Refer to: https://chromedevtools.github.io/devtools-protocol/
//!
//! Taken from: https://github.com/denoland/deno/blob/e96933bc163fd81a276cbc169b17f76724a5ac33/cli/tools/coverage/json_types.rs

#![allow(missing_docs)]

// License text available at: ../../LICENSE-DENO
// Copyright 2018-2022 the Deno authors. All rights reserved. MIT license.

use serde::{Deserialize, Serialize};

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CoverageRange {
    /// Start character index.
    #[serde(rename = "startOffset")]
    pub start_char_offset: usize,
    /// End character index.
    #[serde(rename = "endOffset")]
    pub end_char_offset: usize,
    pub count: i64,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FunctionCoverage {
    pub function_name: String,
    pub ranges: Vec<CoverageRange>,
    pub is_block_coverage: bool,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScriptCoverage {
    pub script_id: String,
    pub url: String,
    pub functions: Vec<FunctionCoverage>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StartPreciseCoverageParameters {
    pub call_count: bool,
    pub detailed: bool,
    pub allow_triggered_updates: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartPreciseCoverageReturnObject {
    pub timestamp: f64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TakePreciseCoverageReturnObject {
    pub result: Vec<ScriptCoverage>,
    pub timestamp: f64,
}

// TODO(bartlomieju): remove me
#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessCoverage {
    pub result: Vec<ScriptCoverage>,
}
