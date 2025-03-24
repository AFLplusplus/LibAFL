use core::{fmt, marker::PhantomData};
use std::{ops::Range, time::Duration};

use hashbrown::{HashMap, HashSet};
use libafl::{
    Error, HasMetadata,
    corpus::{Corpus, CorpusId},
    fuzzer::Evaluator,
    stages::{Restartable, Stage},
    state::{HasCorpus, HasSolutions},
};
use libafl_bolts::{current_time, impl_serdeany};
use libafl_qemu_sys::libafl_get_image_info;
use serde::{Deserialize, Serialize};

use crate::{GuestAddr, Qemu, QemuMappingsViewer, modules::utils::AddressResolver};

pub static mut IS_RCA: bool = false;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
/// Maintains the list of processed corpus or solution entries till now
pub struct RCARestarterMetadata {
    last: Duration,
    done_corpus: HashSet<CorpusId>,
    done_solution: HashSet<CorpusId>,
}

impl_serdeany!(RCARestarterMetadata);

impl RCARestarterMetadata {
    /// constructor
    #[must_use]
    pub fn new() -> Self {
        Self {
            last: current_time(),
            done_corpus: HashSet::default(),
            done_solution: HashSet::default(),
        }
    }

    /// clear history
    pub fn clear(&mut self) {
        self.done_corpus.clear();
        self.done_solution.clear();
    }

    /// check we've scaned this corpus entry
    pub fn corpus_probe(&mut self, id: &CorpusId) -> bool {
        self.done_corpus.contains(id)
    }

    /// check we've scaned this solution entry
    pub fn solution_probe(&mut self, id: &CorpusId) -> bool {
        self.done_solution.contains(id)
    }

    /// mark this corpus entry as finished
    pub fn corpus_finish(&mut self, id: CorpusId) {
        self.done_corpus.insert(id);
    }

    /// mark this solution entry as finished
    pub fn solution_finish(&mut self, id: CorpusId) {
        self.done_solution.insert(id);
    }
}

pub struct RCAStage<I> {
    resolver: AddressResolver,
    phantom: PhantomData<I>,
}

impl<I> Default for RCAStage<I> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I> core::fmt::Debug for RCAStage<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RCAStage")
            .field("phantom", &self.phantom)
            .finish_non_exhaustive()
    }
}

impl<I> RCAStage<I> {
    #[must_use]
    pub fn new() -> Self {
        let qemu = unsafe { Qemu::get_unchecked() };
        let resolver = AddressResolver::new(&qemu);
        Self {
            resolver,
            phantom: PhantomData,
        }
    }
}

impl<I, S> Restartable<S> for RCAStage<I>
where
    S: HasMetadata,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        state.metadata_or_insert_with(RCARestarterMetadata::default);
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

impl<E, EM, I, S, Z> Stage<E, EM, S, Z> for RCAStage<I>
where
    S: HasCorpus<I> + HasSolutions<I> + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
    I: Clone,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), libafl::Error> {
        // enable rca mode
        let helper = state.metadata::<RCARestarterMetadata>()?;
        if current_time() - helper.last < Duration::from_secs(15) {
            // log::info!("no.. not now.. {:#?} {:#?} {:#?}", current_time(), helper.last, current_time() - helper.last);
            return Ok(());
        }

        log::info!("Starting RCA");
        unsafe {
            IS_RCA = true;
        }

        // scan corpus
        let corpus_ids: Vec<CorpusId> = state.corpus().ids().collect();
        for id in corpus_ids {
            {
                let helper = state.metadata_mut::<RCARestarterMetadata>()?;
                if helper.corpus_probe(&id) {
                    continue;
                }
                helper.corpus_finish(id);
            }
            log::info!("Replaying corpus: {id}");
            let input = {
                let mut tc = state.corpus().get(id)?.borrow_mut();
                let input = tc.load_input(state.corpus())?;
                input.clone()
            };

            fuzzer.evaluate_input(state, executor, manager, &input)?;
        }

        // scan solutions
        let solution_ids: Vec<CorpusId> = state.solutions().ids().collect();
        for id in solution_ids {
            {
                let helper = state.metadata_mut::<RCARestarterMetadata>()?;
                if helper.solution_probe(&id) {
                    continue;
                }
                helper.solution_finish(id);
            }
            log::info!("Replaying solution: {id}");
            let input = {
                let mut tc = state.solutions().get(id)?.borrow_mut();
                let input = tc.load_input(state.corpus())?;
                input.clone()
            };

            fuzzer.evaluate_input(state, executor, manager, &input)?;
        }

        let map = state.metadata_mut::<PredicatesMap>()?;
        map.synthesize();
        map.show(&self.resolver);

        // disable rca mode
        unsafe {
            IS_RCA = false;
        }

        let helper = state.metadata_mut::<RCARestarterMetadata>()?;
        helper.last = current_time();

        log::info!("Finished RCA!");
        Ok(())
    }
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QemuMappingsCache {
    executable: Vec<Range<u64>>,
    mapped_initial: Vec<Range<u64>>,
    sharedlib: Vec<Range<u64>>,
    tracking: Vec<Range<u64>>,
}

impl_serdeany!(QemuMappingsCache);

impl QemuMappingsCache {
    #[must_use]
    pub fn new(viewer: &QemuMappingsViewer<'_>, tracking: Vec<Range<u64>>) -> Self {
        let mut executable = vec![];
        let mut mapped_initial: Vec<Range<u64>> = vec![];
        let mut sharedlib = vec![];
        for rg in viewer.mappings() {
            if rg.flags().executable() && rg.path().is_some() {
                executable.push(rg.start()..rg.end());
            }
        }
        for rg in viewer.mappings() {
            mapped_initial.push(rg.start()..rg.end());
        }

        for rg in viewer.mappings() {
            if let Some(p) = rg.path() {
                if p.ends_with(".so") {
                    sharedlib.push(rg.start()..rg.end());
                }
            }
        }

        Self {
            executable,
            mapped_initial,
            tracking,
            sharedlib,
        }
    }

    #[must_use]
    pub fn is_stack_ptr(&self, ptr: u64) -> bool {
        let image_info = unsafe { libafl_get_image_info() };
        let stack_end = unsafe { (*image_info).start_stack };
        let stack_start = unsafe { (*image_info).stack_limit };
        ptr >= stack_start && stack_end >= ptr
    }

    #[must_use]
    pub fn is_rca(&self) -> bool {
        unsafe { IS_RCA }
    }

    #[must_use]
    pub fn is_so(&self, ptr: u64) -> bool {
        for mp in &self.mapped_initial {
            if mp.contains(&ptr) {
                return true;
            }
        }
        return false;
    }

    #[must_use]
    // heap or mmap region
    pub fn is_heap_ptr(&self, ptr: u64) -> bool {
        let mut in_current = false;
        if let Some(qemu) = Qemu::get() {
            let mappings = qemu.mappings();
            for m in mappings {
                let rg = m.start()..m.end();
                if rg.contains(&ptr) {
                    in_current = true;
                }
            }
        } else {
            panic!("Qemu not initialized but in execution!?");
        }

        let mut in_initial = false;
        for mp in &self.mapped_initial {
            if mp.contains(&ptr) {
                in_initial = true;
            }
        }
        if in_current && !in_initial {
            return true;
        }
        false
    }

    #[must_use]
    pub fn is_text_ptr(&self, ptr: u64) -> bool {
        for rg in &self.tracking {
            if rg.contains(&ptr) {
                return true;
            }
        }
        false
    }

    #[must_use]
    pub fn is_executable_ptr(&self, ptr: u64) -> bool {
        for rg in &self.executable {
            if rg.contains(&ptr) {
                return true;
            }
        }
        false
    }
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

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Edges(pub GuestAddr, pub GuestAddr);

/// List of predicates gathered over all runs.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PredicatesMap {
    edges: HashMap<Edges, (usize, usize)>,
    max: HashMap<GuestAddr, Vec<(u64, bool)>>,
    min: HashMap<GuestAddr, Vec<(u64, bool)>>,
    seen_corpus: HashSet<CorpusId>,
    seen_objectives: HashSet<CorpusId>,
    synthesized: Vec<(PredicateType, f64)>,
}

impl PredicatesMap {
    #[must_use]
    pub fn new() -> Self {
        Self {
            edges: HashMap::default(),
            max: HashMap::default(),
            min: HashMap::default(),
            seen_corpus: HashSet::default(),
            seen_objectives: HashSet::default(),
            synthesized: Vec::new(),
        }
    }

    pub fn show(&self, resolver: &AddressResolver) {
        let mut sorted_synthesized: Vec<(PredicateType, f64)> = self.synthesized.clone();
        sorted_synthesized.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        let top10: Vec<(PredicateType, f64)> = sorted_synthesized.into_iter().take(10).collect();

        for (ty, prob) in &top10 {
            let rip = match ty {
                PredicateType::HasEdge(Edges(s, _)) => s,
                PredicateType::MaxGt(addr, _) | PredicateType::MinLt(addr, _) => addr,
            };
            let line = resolver.resolve(*rip);
            let res = format!("{line} {ty:?} \n with probability {prob}");
            println!("{res}");
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

/// List of predicates gathered over during one run
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Tracer {
    edges: Vec<Edges>,
    // Temporal storage to memoize the max value observed in 1 run
    maxmap: HashMap<GuestAddr, u64>,
    // Temporal storage to memoize the min value observed in 1 run
    minmap: HashMap<GuestAddr, u64>,
}
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
