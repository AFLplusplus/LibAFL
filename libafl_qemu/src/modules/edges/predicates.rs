use core::fmt;
use std::borrow::Cow;

use hashbrown::HashMap;
use libafl::{
    corpus::Testcase,
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
    HasMetadata,
};
use libafl_bolts::{impl_serdeany, Named};
use serde::{Deserialize, Serialize};

use crate::GuestAddr;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Edges(GuestAddr, GuestAddr);

/// List of predicates gathered over during one run
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Predicates {
    edges: Vec<Edges>,
    // Temporal storage to memoize the max value observed in 1 run
    maxmap: HashMap<GuestAddr, u64>,
    // Temporal storage to memoize the min value observed in 1 run
    minmap: HashMap<GuestAddr, u64>,
}

/// List of predicates gathered over all runs.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PredicatesMap {
    edges: HashMap<Edges, (usize, usize)>,
    max: HashMap<GuestAddr, Vec<(usize, bool)>>,
    min: HashMap<GuestAddr, Vec<(usize, bool)>>,
}

impl PredicatesMap {
    #[must_use]
    pub fn new() -> Self {
        Self {
            edges: HashMap::default(),
            max: HashMap::default(),
            min: HashMap::default(),
        }
    }

    pub fn generate_predicates() {
        todo!("Actually generate predicates from the info")
    }

    #[allow(clippy::cast_precision_loss)]
    #[deprecated]
    pub fn sort_and_show(&self) {
        let mut entries: Vec<_> = self.edges.iter().collect();

        // Sort entries based on the ratio (first usize) / (second usize)
        entries.sort_by(|a, b| {
            let ratio_a = a.1 .0 as f64 / a.1 .1 as f64;
            let ratio_b = b.1 .0 as f64 / b.1 .1 as f64;
            ratio_b.partial_cmp(&ratio_a).unwrap()
        });

        // Take the top 10 entries (or fewer if there are less than 10)
        let top_30 = entries.iter().take(30);

        println!("Top 10 entries with highest ratio:");
        for (i, (key, (first, second))) in top_30.enumerate() {
            let ratio = *first as f64 / *second as f64;
            println!(
                "{}. {}: ({}, {}) - Ratio: {:.2}",
                i + 1,
                key,
                first,
                second,
                ratio
            );
        }
    }

    /// Take one item from max or min map and find it's divider and its misclassification rate.
    fn select(a: &Vec<usize>, b: &Vec<usize>) {
        let mut merged: Vec<(usize, i32)> = Vec::new();
        for item in a.iter() {
            merged.push((*item, 1)); // crashing guys
        }
        for item in b.iter() {
            merged.push((*item, 0)); // non crashing guys
        }

        merged.sort(); // nlogn no better way than this shit

        let n = a.len(); // total crash
        let m = b.len(); // total safe
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
            if item.1 == 1 {
                x += 1;
            } else {
                y += 1;
            }
        }
        println!("Best selector is {} {}", idx_found, missclassification);
    }
}

impl_serdeany!(PredicatesMap);
impl_serdeany!(Predicates);
impl Predicates {
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
}

impl Named for PredicateFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("predicates")
    }
}

impl PredicateFeedback {
    #[must_use]
    pub fn new() -> Self {
        Self { was_crash: false }
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
            Ok(true)
        } else {
            self.was_crash = false;
            Ok(false)
        }
    }
    fn append_metadata(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        _testcase: &mut Testcase<I>,
    ) -> Result<(), libafl::Error> {
        // do stuf for map
        /*
        let mut predicates = vec![];
        let mut maxs = vec![];
        let mut mins = vec![];
        for predicate in predicates {
            if self.was_crash {
                map.map
                    .entry(predicate)
                    .and_modify(|e| {
                        e.0 += 1;
                        e.1 += 1;
                    })
                    .or_insert((1, 1));
            } else {
                map.map
                    .entry(predicate)
                    .and_modify(|e| e.1 += 1)
                    .or_insert((0, 1));
            }
        }
        */
        let map = state.metadata_or_insert_with(PredicatesMap::new);
        Ok(())
    }
}

impl fmt::Display for Edges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Edges({:#x}, {:#x})", self.0, self.1)
    }
}
