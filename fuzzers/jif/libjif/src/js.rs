use libafl::bolts::tuples::Named;
use libafl::events::EventFirer;
use libafl::executors::ExitKind;
use libafl::feedbacks::Feedback;
use libafl::inputs::Input;
use libafl::observers::Observer;
use libafl::observers::ObserversTuple;
use libafl::state::HasClientPerfMonitor;
use libafl::state::HasMetadata;
use libafl::state::HasNamedMetadata;
use libafl::Error;
use libafl::SerdeAny;
use serde::{Deserialize, Serialize};

use std::cmp::max;
use std::ffi::CStr;
use std::os::raw::c_char;

// This module contains everything needed to do parse chrome's JS "block coverage"
// and provide an Oberserver and Feedback for LibAFL

#[derive(Debug, Serialize, Deserialize)]
pub struct JSObserver {
    name: String,
    js_coverage: String,
}

extern "C" {
    fn get_js_coverage() -> *const c_char;
}

impl<I, S> Observer<I, S> for JSObserver {
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        // we don't currently do much here?
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        unsafe {
            let js_coverage = get_js_coverage();
            if js_coverage.is_null() {
                self.js_coverage = "".to_string();
            } else {
                self.js_coverage = CStr::from_ptr(js_coverage).to_string_lossy().into_owned();
            }
        }
        Ok(())
    }
}

impl Named for JSObserver {
    fn name(&self) -> &str {
        &self.name
    }
}

impl JSObserver {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            js_coverage: String::new(),
        }
    }
}

#[derive(Debug)]
pub struct JSFeedback {
    name: String,
}

impl<I: Input, S: HasClientPerfMonitor + HasMetadata + HasNamedMetadata> Feedback<I, S>
    for JSFeedback
{
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        let observer = observers.match_name::<JSObserver>(&self.name).unwrap();
        let novel = state
            .named_metadata_mut()
            .get_mut::<JSMapState>(&self.name)
            .unwrap()
            .add_coverage(&observer.js_coverage);
        Ok(novel)
    }

    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        state.add_named_metadata(JSMapState::new(&self.name), &self.name);
        Ok(())
    }
}

impl JSFeedback {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

impl Named for JSFeedback {
    fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Serialize, Deserialize, SerdeAny)]
pub struct JSMapState {
    name: String,
    coverage_map: Vec<u8>,
    current_map: Vec<u8>,
}

impl Named for JSMapState {
    fn name(&self) -> &str {
        &self.name
    }
}

impl JSMapState {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            coverage_map: Vec::new(),
            current_map: Vec::new(),
        }
    }

    // add_coverage all the coverage from a JSON string into the current map
    // it returns true if the current map is then novel (along with merging the maps)
    pub fn add_coverage(&mut self, coverage: &str) -> bool {
        if coverage.is_empty() {
            return false;
        }
        self.current_map = Vec::<u8>::new();
        let json: serde_json::Value = serde_json::from_str(coverage).unwrap();
        for v in json["result"].as_array().unwrap().iter() {
            for f in v["functions"].as_array().unwrap().iter() {
                if f["isBlockCoverage"].as_bool().unwrap() {
                    for r in f["ranges"].as_array().unwrap().iter() {
                        // r has three properties we're interested in, start end and count
                        let count = r["count"].as_u64().unwrap();
                        let end = r["endOffset"].as_u64().unwrap();
                        let start = r["startOffset"].as_u64().unwrap();
                        self.add_range_to_current(
                            start.try_into().unwrap(),
                            end.try_into().unwrap(),
                            count,
                        );
                    }
                }
            }
        }
        let novel = compare_maps(&mut self.current_map, &mut self.coverage_map);
        if novel {
            println!("found a novel input!");
            self.coverage_map = merge_maps(&mut self.coverage_map, &mut self.current_map);
        }
        novel
    }

    // adds the range to the current map, including blanking part of it if the count is 0
    // also implements wraparound to 1 addition
    pub fn add_range_to_current(&mut self, start: usize, end: usize, count: u64) {
        if self.current_map.len() < end {
            self.current_map.resize(end, 0);
        }

        for i in start..end {
            if count == 0 {
                self.current_map[i] = 0;
            } else {
                self.current_map[i] = self.current_map[i].wrapping_add((count % 255) as u8);
                if self.current_map[i] == 0 {
                    self.current_map[i] = 1;
                }
            }
        }
    }
}

pub fn merge_maps(coverage_map: &mut Vec<u8>, current_map: &mut Vec<u8>) -> Vec<u8> {
    let size = max(coverage_map.len(), current_map.len());
    let mut merged_map = Vec::new();
    merged_map.resize(size, 0);
    coverage_map.resize(size, 0);
    current_map.resize(size, 0);
    for i in 0..size {
        merged_map[i] = max(coverage_map[i], current_map[i]);
    }
    merged_map
}

// returns true if the current map is novel compared to the coverage map
pub fn compare_maps(current_map: &mut Vec<u8>, coverage_map: &mut Vec<u8>) -> bool {
    if current_map.len() > coverage_map.len() {
        return true;
    }
    current_map.resize(coverage_map.len(), 0);
    for i in 0..current_map.len() {
        if current_map[i] > coverage_map[i] {
            return true;
        }
    }
    false
}
