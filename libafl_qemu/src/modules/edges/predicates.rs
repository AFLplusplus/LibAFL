use std::borrow::Cow;
use core::fmt;
use hashbrown::{HashMap, HashSet};
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
pub enum Predicate {
    Edges(GuestAddr, GuestAddr),
    Max(GuestAddr, u64),
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Predicates {
    predicates: HashSet<Predicate>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct PredicatesMap {
    map: HashMap<Predicate, (usize, usize)>,
}
impl PredicatesMap {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}
impl_serdeany!(PredicatesMap);
impl_serdeany!(Predicates);
impl Predicates {
    pub fn new() -> Self {
        Self {
            predicates: HashSet::new(),
        }
    }
    pub fn add_edges(&mut self, src: GuestAddr, dest: GuestAddr) {
        self.predicates.insert(Predicate::Edges(src, dest));
    }
    pub fn clear(&mut self) {
        self.predicates.clear();
    }
    pub fn predicates(&self) -> &HashSet<Predicate> {
        &self.predicates
    }

    pub fn sort_and_show(&self) {
        let mut entries: Vec<_> = self.map.iter().collect();

        // Sort entries based on the ratio (first usize) / (second usize)
        entries.sort_by(|a, b| {
            let ratio_a = a.1 .0 as f64 / a.1 .1 as f64;
            let ratio_b = b.1 .0 as f64 / b.1 .1 as f64;
            ratio_b.partial_cmp(&ratio_a).unwrap()
        });

        // Take the top 10 entries (or fewer if there are less than 10)
        let top_10 = entries.iter().take(10);

        println!("Top 10 entries with highest ratio:");
        for (i, (key, (first, second))) in top_10.enumerate() {
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
}
pub struct PredicateFeedback {
    was_crash: bool,
}
impl Named for PredicateFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("predicates")
    }
}
impl PredicateFeedback {
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
        match exit_kind {
            ExitKind::Ok => {
                self.was_crash = false;
                Ok(true)
            }
            ExitKind::Crash => {
                self.was_crash = true;
                Ok(true)
            }
            _ => {
                self.was_crash = false;
                Ok(false)
            }
        }
    }
    fn append_metadata(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        _testcase: &mut Testcase<I>,
    ) -> Result<(), libafl::Error> {
        let mut predicates = vec![];
        if let Ok(meta) = state.metadata::<Predicates>() {
            for predicate in &meta.predicates {
                predicates.push(predicate.clone());
            }
        }
        let map = state.metadata_or_insert_with(PredicatesMap::new);
        for predicate in predicates {
            if self.was_crash {
                map.map
                    .entry(predicate)
                    .and_modify(|e| {
                        e.0 += 1;
                        e.1 += 1
                    })
                    .or_insert((1, 1));
            } else {
                map.map
                    .entry(predicate)
                    .and_modify(|e| e.1 += 1)
                    .or_insert((0, 1));
            }
        }
        println!("{:#?}", map);
        Ok(())
    }
}

impl fmt::Display for Predicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Predicate::Edges(addr1, addr2) => write!(f, "Edges({:#x}, {:#x})", addr1, addr2),
            Predicate::Max(addr, value) => write!(f, "Max({:#x}, {:#x})", addr, value),
        }
    }
}
