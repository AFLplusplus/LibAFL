use core::fmt;
use std::{borrow::Cow, ops::Range};

use hashbrown::HashMap;
use libafl::{
    corpus::Testcase,
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
    HasMetadata,
};
use libafl_bolts::{impl_serdeany, Named};
use libafl_qemu_sys::libafl_get_image_info;
use serde::{Deserialize, Serialize};

use crate::GuestAddr;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Edges(GuestAddr, GuestAddr);

/// List of predicates gathered over during one run
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Tracer {
    edges: Vec<Edges>,
    // Temporal storage to memoize the max value observed in 1 run
    maxmap: HashMap<GuestAddr, u64>,
    // Temporal storage to memoize the min value observed in 1 run
    minmap: HashMap<GuestAddr, u64>,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum PredicateType {
    // Has Edge
    HasEdge(Edges),
    // Max is gt than
    MaxGt(GuestAddr, (u64, u64)),
    // Min is lt than
    MinLt(GuestAddr, (u64, u64)),
}

impl fmt::Debug for PredicateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PredicateType::HasEdge(edges) => {
                write!(f, "CRASH if has edge from {:x} to {:x}", edges.0, edges.1)
            }
            PredicateType::MaxGt(addr, value) => {
                write!(
                    f,
                    "Crash if load at addr: {:x} is larger than value: {}-{}",
                    addr, value.0, value.1
                )
            }
            PredicateType::MinLt(addr, value) => {
                write!(
                    f,
                    "Crash if load at addr: {:x} is less than value: {}-{}",
                    addr, value.0, value.1
                )
            }
        }
    }
}

/// Take one item from max map and find it's divider and its misclassification rate.
#[allow(clippy::cast_precision_loss)]
pub fn select_max(merged: &mut [(u64, bool)]) -> ((u64, u64), f64) {
    // check how many crashes
    let mut crashed = 0;
    for (_, b) in merged.iter() {
        if *b {
            crashed += 1;
        }
    }
    merged.sort_by(|a, b| a.0.cmp(&b.0));

    let n = crashed;
    let m = merged.len() - crashed;
    let mut x = 0; // current crash;
    let mut y = 0; // current safe

    // Now we gonna compute x + m - y
    let mut missclassification = n + m;
    let mut idx_found = 0;
    for (idx, item) in merged.iter().enumerate() {
        if x + m - y < missclassification {
            missclassification = x + m - y;
            idx_found = idx;
        }
        if item.1 {
            x += 1;
        } else {
            y += 1;
        }
    }
    // println!("Best selector is {} {}", idx_found, missclassification);
    let end = merged[idx_found].0;
    let start = if let Some(e) = merged.get(idx_found - 1) {
        e.0
    } else {
        u64::MAX
    };
    let mut rate = missclassification as f64 / (n + m) as f64;
    rate = 1.0 - rate;
    ((start, end), rate)
}

/// Take one item from min map and find it's divider and its misclassification rate.
#[allow(clippy::cast_precision_loss)]
pub fn select_min(merged: &mut [(u64, bool)]) -> ((u64, u64), f64) {
    // check how many crashes
    let mut crashed = 0;
    for (_, b) in merged.iter() {
        if *b {
            crashed += 1;
        }
    }
    merged.sort_by(|a, b| a.0.cmp(&b.0));

    let n = crashed;
    let m = merged.len() - crashed;
    let mut x = 0; // current crash;
    let mut y = 0; // current safe

    // Now we gonna compute x + m - y
    let mut missclassification = n + m;
    let mut idx_found = 0;
    for (idx, item) in merged.iter().enumerate() {
        if y + n - x < missclassification {
            missclassification = y + n - x;
            idx_found = idx;
        }
        if item.1 {
            x += 1;
        } else {
            y += 1;
        }
    }
    // println!("Best selector is {} {}", idx_found, missclassification);
    let start = merged[idx_found].0;
    let end = if let Some(e) = merged.get(idx_found + 1) {
        e.0
    } else {
        u64::MIN
    };

    let mut rate = missclassification as f64 / (n + m) as f64;
    rate = 1.0 - rate;
    ((start, end), rate)
}

/// List of predicates gathered over all runs.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PredicatesMap {
    edges: HashMap<Edges, (usize, usize)>,
    max: HashMap<GuestAddr, Vec<(u64, bool)>>,
    min: HashMap<GuestAddr, Vec<(u64, bool)>>,
    synthesized: Vec<(PredicateType, f64)>,
}

impl PredicatesMap {
    #[must_use]
    pub fn new() -> Self {
        Self {
            edges: HashMap::default(),
            max: HashMap::default(),
            min: HashMap::default(),
            synthesized: Vec::new(),
        }
    }

    pub fn show(&self) {
        let mut sorted_synthesized: Vec<(PredicateType, f64)> = self.synthesized.clone();
        sorted_synthesized.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        let top10: Vec<(PredicateType, f64)> = sorted_synthesized.into_iter().take(10).collect();

        for i in &top10 {
            println!("{i:#?}");
        }
    }

    pub fn add_edges(&mut self, edges: Edges, crash: bool) {
        self.edges
            .entry(edges)
            .and_modify(|data| {
                if crash {
                    data.0 += 1;
                    data.1 += 1;
                } else {
                    data.1 += 1;
                }
            })
            .or_insert(if crash { (1, 1) } else { (0, 1) });
    }

    pub fn add_maxes(&mut self, addr: GuestAddr, ma: u64, was_crash: bool) {
        self.max.entry(addr).or_default().push((ma, was_crash));
    }

    pub fn add_mins(&mut self, addr: GuestAddr, mi: u64, was_crash: bool) {
        self.min.entry(addr).or_default().push((mi, was_crash));
    }

    #[allow(clippy::cast_precision_loss)]
    pub fn synthesize(&mut self) {
        let mut synthesized = vec![];
        for (edge, (crash, all)) in &self.edges {
            let pred = PredicateType::HasEdge(*edge);
            synthesized.push((pred, *crash as f64 / *all as f64));
        }
        for (addr, max) in &mut self.max {
            let (divider, rate) = select_max(max);
            let pred = PredicateType::MaxGt(*addr, divider);
            synthesized.push((pred, rate));
        }
        for (addr, min) in &mut self.min {
            let (divider, rate) = select_min(min);
            let pred = PredicateType::MinLt(*addr, divider);
            synthesized.push((pred, rate));
        }
        self.synthesized = synthesized;
    }
}

impl_serdeany!(PredicatesMap);
impl_serdeany!(Tracer);
impl Tracer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            edges: Vec::new(),
            maxmap: HashMap::new(),
            minmap: HashMap::new(),
        }
    }

    pub fn add_edges(&mut self, src: GuestAddr, dest: GuestAddr) {
        self.edges.push(Edges(src, dest));
    }

    /// Reset it (should do it every run)
    pub fn clear(&mut self) {
        self.edges.clear();
        self.maxmap.clear();
        self.minmap.clear();
    }

    pub fn update_max_min(&mut self, addr: GuestAddr, value: u64) {
        // Update maxmap
        self.maxmap
            .entry(addr)
            .and_modify(|max_value| {
                if value > *max_value {
                    *max_value = value;
                }
            })
            .or_insert(value);

        // Update minmap
        self.minmap
            .entry(addr)
            .and_modify(|min_value| {
                if value < *min_value {
                    *min_value = value;
                }
            })
            .or_insert(value);
    }

    #[must_use]
    pub fn edges(&self) -> &Vec<Edges> {
        &self.edges
    }

    #[must_use]
    pub fn maxmap(&self) -> &HashMap<GuestAddr, u64> {
        &self.maxmap
    }

    #[must_use]
    pub fn minmap(&self) -> &HashMap<GuestAddr, u64> {
        &self.minmap
    }
}

#[derive(Default)]
pub struct PredicateFeedback {
    was_crash: bool,
    tracking_ip: Range<u64>,
}

impl Named for PredicateFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("predicates")
    }
}

impl PredicateFeedback {
    #[must_use]
    pub fn new(range: Range<u64>) -> Self {
        Self {
            was_crash: false,
            tracking_ip: range,
        } // sane default
    }

    #[must_use]
    pub fn is_stack_ptr(&self, ptr: u64) -> bool {
        let image_info = unsafe { libafl_get_image_info() };
        let stack_end = unsafe { (*image_info).start_stack };
        let stack_start = unsafe { (*image_info).stack_limit };
        ptr >= stack_start && stack_end >= ptr
    }
    #[must_use]
    pub fn is_text_ptr(&self, ptr: u64) -> bool {
        self.tracking_ip.contains(&ptr)
    }
}

impl<S> StateInitializer<S> for PredicateFeedback {}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for PredicateFeedback
where
    S: HasMetadata,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, libafl::Error> {
        if exit_kind == &ExitKind::Crash {
            self.was_crash = true;
        } else {
            self.was_crash = false;
        }
        Ok(false)
    }
    fn append_metadata(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        _testcase: &mut Testcase<I>,
    ) -> Result<(), libafl::Error> {
        let tracer = state.metadata::<Tracer>().unwrap();
        // because of double borrow shit!
        println!("{:#?}", self.tracking_ip);
        let mut edges = vec![];
        let mut maxes = vec![];
        let mut mins = vec![];
        for e in tracer.edges() {
            if self.is_text_ptr(e.0) && self.is_text_ptr(e.1) {
                edges.push(*e);
            }
        }
        for (addr, ma) in tracer.maxmap() {
            if !self.is_stack_ptr(*ma) && self.is_text_ptr(*addr) {
                maxes.push((*addr, *ma));
            }
        }
        for (addr, mi) in tracer.minmap() {
            if !self.is_stack_ptr(*mi) && self.is_text_ptr(*addr) {
                mins.push((*addr, *mi));
            }
        }

        let map = state.metadata_or_insert_with(PredicatesMap::new);

        for e in edges {
            map.add_edges(e, self.was_crash);
        }
        for (addr, ma) in maxes {
            map.add_maxes(addr, ma, self.was_crash);
        }
        for (addr, mi) in mins {
            map.add_mins(addr, mi, self.was_crash);
        }
        map.synthesize();
        // println!("{:#?}", map.max);
        // println!("{:#?}", map.min);
        map.show();
        Ok(())
    }
}

impl fmt::Display for Edges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Edges({:#x}, {:#x})", self.0, self.1)
    }
}
