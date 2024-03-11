//! The colorization stage from `colorization()` in afl++
use alloc::{
    collections::binary_heap::BinaryHeap,
    string::{String, ToString},
    vec::Vec,
};
use core::{cmp::Ordering, fmt::Debug, marker::PhantomData, ops::Range};

use libafl_bolts::{rands::Rand, tuples::MatchName, Named};
use serde::{Deserialize, Serialize};

use crate::{
    events::EventFirer,
    executors::{Executor, HasObservers},
    inputs::HasBytesVec,
    mutators::mutations::buffer_copy,
    observers::{MapObserver, ObserversTuple},
    stages::{RetryRestartHelper, Stage},
    state::{HasCorpus, HasCurrentTestcase, HasMetadata, HasNamedMetadata, HasRand, UsesState},
    Error,
};

// Bigger range is better
#[derive(Debug, PartialEq, Eq)]
struct Bigger(Range<usize>);

impl PartialOrd for Bigger {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
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
        Some(self.cmp(other))
    }
}

impl Ord for Earlier {
    fn cmp(&self, other: &Self) -> Ordering {
        other.0.start.cmp(&self.0.start)
    }
}

/// The mutational stage using power schedules
#[derive(Clone, Debug)]
pub struct ColorizationStage<EM, O, E, Z> {
    map_observer_name: String,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, O, Z)>,
}

impl<EM, O, E, Z> UsesState for ColorizationStage<EM, O, E, Z>
where
    E: UsesState,
{
    type State = E::State;
}

impl<EM, O, E, Z> Named for ColorizationStage<EM, O, E, Z>
where
    E: UsesState,
{
    fn name(&self) -> &str {
        &self.map_observer_name
    }
}

impl<E, EM, O, Z> Stage<E, EM, Z> for ColorizationStage<EM, O, E, Z>
where
    EM: UsesState<State = E::State> + EventFirer,
    E: HasObservers + Executor<EM, Z>,
    E::State: HasCorpus + HasMetadata + HasRand + HasNamedMetadata,
    E::Input: HasBytesVec,
    O: MapObserver,
    Z: UsesState<State = E::State>,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E, // don't need the *main* executor for tracing
        state: &mut E::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        // Run with the mutated input
        Self::colorize(fuzzer, executor, state, manager, &self.map_observer_name)?;

        Ok(())
    }

    fn restart_progress_should_run(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        // TODO this stage needs a proper resume
        RetryRestartHelper::restart_progress_should_run(state, self, 3)
    }

    fn clear_restart_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        // TODO this stage needs a proper resume
        RetryRestartHelper::clear_restart_progress(state, self)
    }
}

/// Store the taint and the input
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct TaintMetadata {
    input_vec: Vec<u8>,
    ranges: Vec<Range<usize>>,
}

impl TaintMetadata {
    #[must_use]
    /// Constructor for taint metadata
    pub fn new(input_vec: Vec<u8>, ranges: Vec<Range<usize>>) -> Self {
        Self { input_vec, ranges }
    }

    /// Set input and ranges
    pub fn update(&mut self, input: Vec<u8>, ranges: Vec<Range<usize>>) {
        self.input_vec = input;
        self.ranges = ranges;
    }

    #[must_use]
    /// Getter for `input_vec`
    pub fn input_vec(&self) -> &Vec<u8> {
        &self.input_vec
    }

    #[must_use]
    /// Getter for `ranges`
    pub fn ranges(&self) -> &Vec<Range<usize>> {
        &self.ranges
    }
}

libafl_bolts::impl_serdeany!(TaintMetadata);

impl<EM, O, E, Z> ColorizationStage<EM, O, E, Z>
where
    EM: UsesState<State = E::State> + EventFirer,
    O: MapObserver,
    E: HasObservers + Executor<EM, Z>,
    E::State: HasCorpus + HasMetadata + HasRand,
    E::Input: HasBytesVec,
    Z: UsesState<State = E::State>,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn colorize(
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
        name: &str,
    ) -> Result<E::Input, Error> {
        let mut input = state.current_input_cloned()?;
        // The backup of the input
        let backup = input.clone();
        // This is the buffer we'll randomly mutate during type_replace
        let mut changed = input.clone();

        // input will be consumed so clone it
        let consumed_input = input.clone();

        // First, run orig_input once and get the original hash

        // Idea: No need to do this every time
        let orig_hash =
            Self::get_raw_map_hash_run(fuzzer, executor, state, manager, consumed_input, name)?;
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

        // println!("Replaced bytes: {:#?}", changed_bytes);
        // Now replace with random values (This is type_replace)
        Self::type_replace(changed_bytes, state);

        // println!("Replaced bytes: {:#?}", changed_bytes);
        // What we do is now to separate the input into smaller regions
        // And in each small regions make sure changing those bytes in the regions does not affect the coverage
        for _ in 0..input_len * 2 {
            if let Some(b) = ranges.pop() {
                // Let's try the largest one (ranges is sorted)
                let r = b.0;
                let range_start = r.start;
                let range_end = r.end;
                let copy_len = r.len();
                unsafe {
                    buffer_copy(
                        input.bytes_mut(),
                        changed.bytes(),
                        range_start,
                        range_start,
                        copy_len,
                    );
                }

                let consumed_input = input.clone();
                let changed_hash = Self::get_raw_map_hash_run(
                    fuzzer,
                    executor,
                    state,
                    manager,
                    consumed_input,
                    name,
                )?;

                if orig_hash == changed_hash {
                    // The change in this range is safe!
                    // println!("this range safe to change: {:#?}", range_start..range_end);

                    ok_ranges.push(Earlier(range_start..range_end));
                } else {
                    // Seems like this range is too big that we can't keep the original hash anymore

                    // Revert the changes
                    unsafe {
                        buffer_copy(
                            input.bytes_mut(),
                            backup.bytes(),
                            range_start,
                            range_start,
                            copy_len,
                        );
                    }

                    // Add smaller range
                    if copy_len > 1 {
                        // Separate the ranges
                        ranges.push(Bigger(range_start..(range_start + copy_len / 2)));
                        ranges.push(Bigger((range_start + copy_len / 2)..range_end));
                    }
                }
            } else {
                break;
            }
        }

        // Now ok_ranges is a list of smaller range
        // Each of them should be stored into a metadata and we'll use them later in afl++ redqueen

        // let's merge ranges in ok_ranges
        let mut res: Vec<Range<usize>> = Vec::new();
        for item in ok_ranges.into_sorted_vec().into_iter().rev() {
            match res.last_mut() {
                Some(last) => {
                    // Try merge
                    if last.end == item.0.start {
                        // The last one in `res` is the start of the new one
                        // so merge
                        last.end = item.0.end;
                    } else {
                        res.push(item.0);
                    }
                }
                None => {
                    res.push(item.0);
                }
            }
        }

        if let Some(meta) = state.metadata_map_mut().get_mut::<TaintMetadata>() {
            meta.update(input.bytes().to_vec(), res);

            // println!("meta: {:#?}", meta);
        } else {
            let meta = TaintMetadata::new(input.bytes().to_vec(), res);
            state.add_metadata::<TaintMetadata>(meta);
        }

        Ok(input)
    }

    #[must_use]
    /// Creates a new [`ColorizationStage`]
    pub fn new(map_observer_name: &O) -> Self {
        Self {
            map_observer_name: map_observer_name.name().to_string(),
            phantom: PhantomData,
        }
    }

    // Run the target and get map hash but before hitcounts's post_exec is used
    fn get_raw_map_hash_run(
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
        input: E::Input,
        name: &str,
    ) -> Result<usize, Error> {
        executor.observers_mut().pre_exec_all(state, &input)?;

        let exit_kind = executor.run_target(fuzzer, state, manager, &input)?;

        let observer = executor
            .observers()
            .match_name::<O>(name)
            .ok_or_else(|| Error::key_not_found("MapObserver not found".to_string()))?;

        let hash = observer.hash() as usize;

        executor
            .observers_mut()
            .post_exec_all(state, &input, &exit_kind)?;

        // let observers = executor.observers();
        // fuzzer.process_execution(state, manager, input, observers, &exit_kind, true)?;

        Ok(hash)
    }

    /// Replace bytes with random values but following certain rules
    #[allow(clippy::needless_range_loop)]
    fn type_replace(bytes: &mut [u8], state: &mut E::State) {
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
                0x1 | 0xff => 0x0,
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
