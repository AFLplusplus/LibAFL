//! The colorization stage from colorization() in afl++
use alloc::{
    collections::binary_heap::BinaryHeap,
    string::{String, ToString},
    vec::Vec,
};
use core::{cmp::Ordering, fmt::Debug, marker::PhantomData, ops::Range};

use crate::{
    bolts::{rands::Rand, tuples::MatchName},
    corpus::{Corpus, CorpusId},
    executors::{Executor, HasObservers},
    fuzzer::Evaluator,
    inputs::HasBytesVec,
    mutators::mutations::buffer_copy,
    observers::MapObserver,
    stages::Stage,
    state::{HasClientPerfMonitor, HasCorpus, HasMetadata, HasRand, UsesState},
    Error,
};

// Bigger range is better
#[derive(Debug, PartialEq, Eq)]
struct Bigger(Range<usize>);

impl PartialOrd for Bigger {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.len().partial_cmp(&other.0.len())
    }
}

impl Ord for Bigger {
    fn cmp(&self, other: &Bigger) -> Ordering {
        self.0.len().cmp(&other.0.len())
    }
}

// Earlier range is better
#[derive(Debug, PartialEq, Eq)]
struct Earlier(Range<usize>);

impl PartialOrd for Earlier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        other.0.start.partial_cmp(&self.0.start)
    }
}

impl Ord for Earlier {
    fn cmp(&self, other: &Self) -> Ordering {
        other.0.start.cmp(&self.0.start)
    }
}

/// The mutational stage using power schedules
#[derive(Clone, Debug)]
pub struct ColorizationStage<E, EM, O, Z> {
    map_observer_name: String,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, O, Z)>,
}

impl<E, EM, O, Z> UsesState for ColorizationStage<E, EM, O, Z>
where
    E: UsesState,
{
    type State = E::State;
}

impl<E, EM, O, Z> Stage<E, EM, Z> for ColorizationStage<E, EM, O, Z>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = E::State>,
    O: MapObserver,
    E::State: HasClientPerfMonitor + HasCorpus + HasMetadata + HasRand,
    Z: Evaluator<E, EM, State = E::State>,
    E::Input: HasBytesVec,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        let input = state
            .corpus()
            .get(corpus_idx)?
            .borrow_mut()
            .load_input()
            .unwrap()
            .clone();
        // The backup of the input
        let backup = input.clone();
        // This is the buffer we'll randomly mutate during type_replace
        let mut changed = input.clone();
        // This is the buffer we want to pass to the cmplog stage
        let mut buf = input.clone();

        // First, run orig_input once and get the original hash
        let (_, _) = fuzzer.evaluate_input(state, executor, manager, input)?;

        let observer = executor
            .observers()
            .match_name::<O>(&self.map_observer_name)
            .ok_or_else(|| Error::key_not_found("MapObserver not found".to_string()))?;

        let orig_hash = observer.hash() as usize;

        let changed_bytes = changed.bytes_mut();
        let input_len = changed_bytes.len();

        // Binary heap, pop is logN, insert is logN
        // We will separate this range into smaller ranges.
        // Keep it sorted, we want biggest ones to come first
        let mut ranges = BinaryHeap::new();
        ranges.push(Bigger(0..input_len));

        // This heap contains the smaller ranges. Changes inside them does not affect the coverage.
        // Keep it sorted, we want the earliest ones to come first so that it's easier to sort them
        let mut ok_ranges = BinaryHeap::new();

        // Now replace with random values (This is type_replace)
        self.type_replace(changed_bytes, state);

        // What we do is now to separate the input into smaller regions
        // And in each small regions make sure changing those bytes in the regions does not affect the coverage
        for _ in 0..input_len * 2 {
            if let Some(b) = ranges.pop() {
                // Let's try the largest one (ranges is sorted)
                let r = b.0;
                let range_start = r.start;
                let range_end = r.end;
                let copy_len = r.len();
                buffer_copy(
                    buf.bytes_mut(),
                    changed.bytes(),
                    range_start,
                    range_start,
                    copy_len,
                );

                // We need to clone buf because evaluate_input will consume input (we can't use buf in evaluate_input)
                let input = buf.clone();
                let (_, _) = fuzzer.evaluate_input(state, executor, manager, input)?;

                let observer = executor
                    .observers()
                    .match_name::<O>(&self.map_observer_name)
                    .ok_or_else(|| Error::key_not_found("MapObserver not found".to_string()))?;

                let changed_hash = observer.hash() as usize;

                if orig_hash != changed_hash {
                    // Ok seems like this range is too big that we can't keep the original hash anymore

                    // Revert the changes
                    buffer_copy(
                        buf.bytes_mut(),
                        backup.bytes(),
                        range_start,
                        range_start,
                        copy_len,
                    );

                    // Add smaller range
                    if copy_len > 1 {
                        // Separate the ranges
                        ranges.push(Bigger(range_start..(range_start + copy_len / 2)));
                        ranges.push(Bigger((range_start + copy_len / 2)..range_end));
                    }
                } else {
                    // The change in this range is safe!
                    ok_ranges.push(Earlier(range_start..range_end));
                }
            } else {
                break;
            }
        }

        // Now ok_ranges is a list of smaller range
        // Each of them should be stored into a metadata and we'll use them later in afl++ redqueen

        // let's merge ranges in ok_ranges
        let mut res: Vec<Range<usize>> = Vec::new();
        for item in ok_ranges.into_sorted_vec() {
            match res.last_mut() {
                Some(last) => {
                    // Try merge
                    if last.end == item.0.start {
                        // The last one in `res` is the start of the new one
                        // so merge
                        last.end = item.0.end;
                    } else {
                        res.push(item.0)
                    }
                }
                None => {
                    res.push(item.0);
                }
            }
        }

        Ok(())
    }
}

impl<E, EM, O, Z> ColorizationStage<E, EM, O, Z>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = E::State>,
    O: MapObserver,
    E::State: HasClientPerfMonitor + HasCorpus + HasMetadata + HasRand,
    Z: Evaluator<E, EM, State = E::State>,
{
    /// Creates a new [`ColorizationStage`]
    pub fn new(map_observer_name: &O) -> Self {
        Self {
            map_observer_name: map_observer_name.name().to_string(),
            phantom: PhantomData,
        }
    }

    /// Replace bytes with random values but following certain rules
    pub fn type_replace(&self, bytes: &mut [u8], state: &mut E::State) {
        let len = bytes.len();
        for idx in 0..len {
            let c = match bytes[idx] {
                0x41..=0x46 => {
                    // 'A' + 1 + rand('F' - 'A')
                    0x41 + 1 + state.rand_mut().below(5) as u8
                }
                0x61..=0x66 => {
                    // 'a' + 1 + rand('f' - 'a')
                    0x61 + 1 + state.rand_mut().below(5) as u8
                }
                0x30 => {
                    // '0' -> '1'
                    0x31
                }
                0x31 => {
                    // '1' -> '0'
                    0x30
                }
                0x32..=0x39 => {
                    // '2' + 1 + rand('9' - '2')
                    0x32 + 1 + state.rand_mut().below(7) as u8
                }
                0x47..=0x5a => {
                    // 'G' + 1 + rand('Z' - 'G')
                    0x47 + 1 + state.rand_mut().below(19) as u8
                }
                0x67..=0x7a => {
                    // 'g' + 1 + rand('z' - 'g')
                    0x67 + 1 + state.rand_mut().below(19) as u8
                }
                0x21..=0x2a => {
                    // '!' + 1 + rand('*' - '!');
                    0x21 + 1 + state.rand_mut().below(9) as u8
                }
                0x2c..=0x2e => {
                    // ',' + 1 + rand('.' - ',')
                    0x2c + 1 + state.rand_mut().below(2) as u8
                }
                0x3a..=0x40 => {
                    // ':' + 1 + rand('@' - ':')
                    0x3a + 1 + state.rand_mut().below(6) as u8
                }
                0x5b..=0x60 => {
                    // '[' + 1 + rand('`' - '[')
                    0x5b + 1 + state.rand_mut().below(5) as u8
                }
                0x7b..=0x7e => {
                    // '{' + 1 + rand('~' - '{')
                    0x7b + 1 + state.rand_mut().below(3) as u8
                }
                0x2b => {
                    // '+' -> '/'
                    0x2f
                }
                0x2f => {
                    // '/' -> '+'
                    0x2b
                }
                0x20 => {
                    // ' ' -> '\t'
                    0x9
                }
                0x9 => {
                    // '\t' -> ' '
                    0x20
                }
                0xd => {
                    // '\r' -> '\n'
                    0xa
                }
                0xa => {
                    // '\n' -> '\r'
                    0xd
                }
                0x0 => 0x1,
                0x1 => 0x0,
                0xff => 0x0,
                _ => {
                    if bytes[idx] < 32 {
                        bytes[idx] ^ 0x1f
                    } else {
                        bytes[idx] ^ 0x7f
                    }
                }
            };

            bytes[idx] = c;
        }
    }
}
