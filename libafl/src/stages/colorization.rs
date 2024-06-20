//! The colorization stage from `colorization()` in afl++
use alloc::{
    borrow::{Cow, ToOwned},
    collections::binary_heap::BinaryHeap,
    vec::Vec,
};
use core::{cmp::Ordering, fmt::Debug, marker::PhantomData, ops::Range};

use libafl_bolts::{
    rands::Rand,
    tuples::{Handle, Handled},
    Named,
};
use serde::{Deserialize, Serialize};

use crate::{
    events::EventFirer,
    executors::{Executor, HasObservers},
    inputs::HasMutatorBytes,
    mutators::mutations::buffer_copy,
    observers::{MapObserver, ObserversTuple},
    stages::{Stage, StdRestartHelper},
    state::{HasCorpus, HasCurrentTestcase, HasRand, UsesState},
    Error, HasMetadata, HasNamedMetadata,
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

/// Default name for `ColorizationStage`; derived from ALF++
pub const COLORIZATION_STAGE_NAME: &str = "colorization";
/// The mutational stage using power schedules
#[derive(Clone, Debug)]
pub struct ColorizationStage<C, E, EM, O, Z> {
    map_observer_handle: Handle<C>,
    name: Cow<'static, str>,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, O, E, Z)>,
}

impl<C, E, EM, O, Z> UsesState for ColorizationStage<C, E, EM, O, Z>
where
    E: UsesState,
{
    type State = E::State;
}

impl<C, E, EM, O, Z> Named for ColorizationStage<C, E, EM, O, Z>
where
    E: UsesState,
{
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<C, E, EM, O, Z> Stage<E, EM, Z> for ColorizationStage<C, E, EM, O, Z>
where
    EM: UsesState<State = Self::State> + EventFirer,
    E: HasObservers + Executor<EM, Z>,
    Self::State: HasCorpus + HasMetadata + HasRand + HasNamedMetadata,
    E::Input: HasMutatorBytes,
    O: MapObserver,
    C: AsRef<O> + Named,
    Z: UsesState<State = Self::State>,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E, // don't need the *main* executor for tracing
        state: &mut Self::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        // Run with the mutated input
        Self::colorize(fuzzer, executor, state, manager, &self.map_observer_handle)?;

        Ok(())
    }

    fn should_restart(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        // This is a deterministic stage
        // Once it failed, then don't retry,
        // It will just fail again
        StdRestartHelper::no_retry(state, &self.name)
    }

    fn clear_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        StdRestartHelper::clear_progress(state, &self.name)
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

impl<C, E, EM, O, Z> ColorizationStage<C, E, EM, O, Z>
where
    EM: UsesState<State = <Self as UsesState>::State> + EventFirer,
    O: MapObserver,
    C: AsRef<O> + Named,
    E: HasObservers + Executor<EM, Z>,
    <Self as UsesState>::State: HasCorpus + HasMetadata + HasRand,
    E::Input: HasMutatorBytes,
    Z: UsesState<State = <Self as UsesState>::State>,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn colorize(
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut <Self as UsesState>::State,
        manager: &mut EM,
        observer_handle: &Handle<C>,
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
        let orig_hash = Self::get_raw_map_hash_run(
            fuzzer,
            executor,
            state,
            manager,
            consumed_input,
            observer_handle,
        )?;
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
                    observer_handle,
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
    pub fn new(map_observer: &C) -> Self {
        let obs_name = map_observer.name().clone().into_owned();
        Self {
            map_observer_handle: map_observer.handle(),
            name: Cow::Owned(COLORIZATION_STAGE_NAME.to_owned() + ":" + obs_name.as_str()),
            phantom: PhantomData,
        }
    }

    // Run the target and get map hash but before hitcounts's post_exec is used
    fn get_raw_map_hash_run(
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut <Self as UsesState>::State,
        manager: &mut EM,
        input: E::Input,
        observer_handle: &Handle<C>,
    ) -> Result<usize, Error> {
        executor.observers_mut().pre_exec_all(state, &input)?;

        let exit_kind = executor.run_target(fuzzer, state, manager, &input)?;

        let observers = executor.observers();
        let observer = observers[observer_handle].as_ref();

        let hash = observer.hash_simple() as usize;

        executor
            .observers_mut()
            .post_exec_all(state, &input, &exit_kind)?;

        // let observers = executor.observers();
        // fuzzer.process_execution(state, manager, input, observers, &exit_kind, true)?;

        Ok(hash)
    }

    /// Replace bytes with random values but following certain rules
    #[allow(clippy::needless_range_loop)]
    fn type_replace(bytes: &mut [u8], state: &mut <Self as UsesState>::State) {
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
