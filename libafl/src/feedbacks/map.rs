//! Map feedback, maximizing or minimizing maps, for example the afl-style map observer.

use alloc::{borrow::Cow, vec::Vec};
#[rustversion::nightly]
use core::simd::prelude::SimdOrd;
use core::{
    fmt::Debug,
    marker::PhantomData,
    ops::{BitAnd, BitOr, Deref, DerefMut},
};

#[rustversion::nightly]
use libafl_bolts::AsSlice;
use libafl_bolts::{
    tuples::{Handle, Handled, MatchNameRef},
    AsIter, HasRefCnt, Named,
};
use num_traits::PrimInt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    corpus::Testcase,
    events::{Event, EventFirer},
    executors::ExitKind,
    feedbacks::{Feedback, HasObserverHandle},
    inputs::UsesInput,
    monitors::{AggregatorOps, UserStats, UserStatsValue},
    observers::{CanTrack, MapObserver, Observer, ObserversTuple},
    state::State,
    Error, HasMetadata, HasNamedMetadata,
};

/// A [`MapFeedback`] that implements the AFL algorithm using an [`OrReducer`] combining the bits for the history map and the bit from (`HitcountsMapObserver`)[`crate::observers::HitcountsMapObserver`].
pub type AflMapFeedback<C, O, T> = MapFeedback<C, DifferentIsNovel, O, OrReducer, T>;

/// A [`MapFeedback`] that strives to maximize the map contents.
pub type MaxMapFeedback<C, O, T> = MapFeedback<C, DifferentIsNovel, O, MaxReducer, T>;
/// A [`MapFeedback`] that strives to minimize the map contents.
pub type MinMapFeedback<C, O, T> = MapFeedback<C, DifferentIsNovel, O, MinReducer, T>;

/// A [`MapFeedback`] that always returns `true` for `is_interesting`. Useful for tracing all executions.
pub type AlwaysInterestingMapFeedback<C, O, T> = MapFeedback<C, AllIsNovel, O, NopReducer, T>;

/// A [`MapFeedback`] that strives to maximize the map contents,
/// but only, if a value is larger than `pow2` of the previous.
pub type MaxMapPow2Feedback<C, O, T> = MapFeedback<C, NextPow2IsNovel, O, MaxReducer, T>;
/// A [`MapFeedback`] that strives to maximize the map contents,
/// but only, if a value is larger than `pow2` of the previous.
pub type MaxMapOneOrFilledFeedback<C, O, T> = MapFeedback<C, OneOrFilledIsNovel, O, MaxReducer, T>;

/// A `Reducer` function is used to aggregate values for the novelty search
pub trait Reducer<T>: 'static
where
    T: Default + Copy + 'static,
{
    /// Reduce two values to one value, with the current [`Reducer`].
    fn reduce(first: T, second: T) -> T;
}

/// A [`OrReducer`] reduces the values returning the bitwise OR with the old value
#[derive(Clone, Debug)]
pub struct OrReducer {}

impl<T> Reducer<T> for OrReducer
where
    T: BitOr<Output = T> + Default + Copy + 'static + PartialOrd,
{
    #[inline]
    fn reduce(history: T, new: T) -> T {
        history | new
    }
}

/// A [`AndReducer`] reduces the values returning the bitwise AND with the old value
#[derive(Clone, Debug)]
pub struct AndReducer {}

impl<T> Reducer<T> for AndReducer
where
    T: BitAnd<Output = T> + Default + Copy + 'static + PartialOrd,
{
    #[inline]
    fn reduce(history: T, new: T) -> T {
        history & new
    }
}

/// A [`NopReducer`] does nothing, and just "reduces" to the second/`new` value.
#[derive(Clone, Debug)]
pub struct NopReducer {}

impl<T> Reducer<T> for NopReducer
where
    T: Default + Copy + 'static,
{
    #[inline]
    fn reduce(_history: T, new: T) -> T {
        new
    }
}

/// A [`MaxReducer`] reduces int values and returns their maximum.
#[derive(Clone, Debug)]
pub struct MaxReducer {}

impl<T> Reducer<T> for MaxReducer
where
    T: Default + Copy + 'static + PartialOrd,
{
    #[inline]
    fn reduce(first: T, second: T) -> T {
        if first > second {
            first
        } else {
            second
        }
    }
}

/// A [`MinReducer`] reduces int values and returns their minimum.
#[derive(Clone, Debug)]
pub struct MinReducer {}

impl<T> Reducer<T> for MinReducer
where
    T: Default + Copy + 'static + PartialOrd,
{
    #[inline]
    fn reduce(first: T, second: T) -> T {
        if first < second {
            first
        } else {
            second
        }
    }
}

/// A `IsNovel` function is used to discriminate if a reduced value is considered novel.
pub trait IsNovel<T>: 'static
where
    T: Default + Copy + 'static,
{
    /// If a new value in the [`MapFeedback`] was found,
    /// this filter can decide if the result is considered novel or not.
    fn is_novel(old: T, new: T) -> bool;
}

/// [`AllIsNovel`] consider everything a novelty. Here mostly just for debugging.
#[derive(Clone, Debug)]
pub struct AllIsNovel {}

impl<T> IsNovel<T> for AllIsNovel
where
    T: Default + Copy + 'static,
{
    #[inline]
    fn is_novel(_old: T, _new: T) -> bool {
        true
    }
}

/// Calculate the next power of two
/// See <https://stackoverflow.com/a/66253960/1345238>
/// Will saturate at the max value.
/// In case of negative values, returns 1.
#[inline]
fn saturating_next_power_of_two<T: PrimInt>(n: T) -> T {
    if n <= T::one() {
        T::one()
    } else {
        (T::max_value() >> (n - T::one()).leading_zeros().try_into().unwrap())
            .saturating_add(T::one())
    }
}

/// Consider as novelty if the reduced value is different from the old value.
#[derive(Clone, Debug)]
pub struct DifferentIsNovel {}

impl<T> IsNovel<T> for DifferentIsNovel
where
    T: PartialEq + Default + Copy + 'static,
{
    #[inline]
    fn is_novel(old: T, new: T) -> bool {
        old != new
    }
}

/// Only consider as novel the values which are at least the next pow2 class of the old value
#[derive(Clone, Debug)]
pub struct NextPow2IsNovel {}

impl<T> IsNovel<T> for NextPow2IsNovel
where
    T: PrimInt + Default + Copy + 'static,
{
    #[inline]
    fn is_novel(old: T, new: T) -> bool {
        // We use a trait so we build our numbers from scratch here.
        // This way it works with Nums of any size.
        if new <= old {
            false
        } else {
            let pow2 = saturating_next_power_of_two(old.saturating_add(T::one()));
            new >= pow2
        }
    }
}

/// Only consider `T::one()` or `T::max_value()`, if they are bigger than the old value, as novel
#[derive(Clone, Debug)]
pub struct OneOrFilledIsNovel {}

impl<T> IsNovel<T> for OneOrFilledIsNovel
where
    T: PrimInt + Default + Copy + 'static,
{
    #[inline]
    fn is_novel(old: T, new: T) -> bool {
        (new == T::one() || new == T::max_value()) && new > old
    }
}

/// A testcase metadata holding a list of indexes of a map
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct MapIndexesMetadata {
    /// The list of indexes.
    pub list: Vec<usize>,
    /// A refcount used to know when we can remove this metadata
    pub tcref: isize,
}

libafl_bolts::impl_serdeany!(MapIndexesMetadata);

impl Deref for MapIndexesMetadata {
    type Target = [usize];
    /// Convert to a slice
    fn deref(&self) -> &[usize] {
        &self.list
    }
}

impl DerefMut for MapIndexesMetadata {
    /// Convert to a slice
    fn deref_mut(&mut self) -> &mut [usize] {
        &mut self.list
    }
}

impl HasRefCnt for MapIndexesMetadata {
    fn refcnt(&self) -> isize {
        self.tcref
    }

    fn refcnt_mut(&mut self) -> &mut isize {
        &mut self.tcref
    }
}

impl MapIndexesMetadata {
    /// Creates a new [`struct@MapIndexesMetadata`].
    #[must_use]
    pub fn new(list: Vec<usize>) -> Self {
        Self { list, tcref: 0 }
    }
}

/// A testcase metadata holding a list of indexes of a map
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct MapNoveltiesMetadata {
    /// A `list` of novelties.
    pub list: Vec<usize>,
}

libafl_bolts::impl_serdeany!(MapNoveltiesMetadata);

impl Deref for MapNoveltiesMetadata {
    type Target = [usize];
    /// Convert to a slice
    #[must_use]
    fn deref(&self) -> &[usize] {
        &self.list
    }
}

impl DerefMut for MapNoveltiesMetadata {
    /// Convert to a slice
    #[must_use]
    fn deref_mut(&mut self) -> &mut [usize] {
        &mut self.list
    }
}

impl MapNoveltiesMetadata {
    /// Creates a new [`struct@MapNoveltiesMetadata`]
    #[must_use]
    pub fn new(list: Vec<usize>) -> Self {
        Self { list }
    }
}

/// The state of [`MapFeedback`]
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "T: DeserializeOwned")]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct MapFeedbackMetadata<T>
where
    T: Default + Copy + 'static + Serialize,
{
    /// Contains information about untouched entries
    pub history_map: Vec<T>,
    /// Tells us how many non-initial entries there are in `history_map`
    pub num_covered_map_indexes: usize,
}

libafl_bolts::impl_serdeany!(
    MapFeedbackMetadata<T: Debug + Default + Copy + 'static + Serialize + DeserializeOwned>,
    <u8>,<u16>,<u32>,<u64>,<i8>,<i16>,<i32>,<i64>,<f32>,<f64>,<bool>,<char>,<usize>
);

impl<T> MapFeedbackMetadata<T>
where
    T: Default + Copy + 'static + Serialize + DeserializeOwned + PartialEq,
{
    /// Create new `MapFeedbackMetadata`
    #[must_use]
    pub fn new(map_size: usize) -> Self {
        Self {
            history_map: vec![T::default(); map_size],
            num_covered_map_indexes: 0,
        }
    }

    /// Create new `MapFeedbackMetadata` using a name and a map.
    /// The map can be shared.
    /// `initial_elem_value` is used to calculate `Self.num_covered_map_indexes`
    #[must_use]
    pub fn with_history_map(history_map: Vec<T>, initial_elem_value: T) -> Self {
        let num_covered_map_indexes = history_map
            .iter()
            .fold(0, |acc, x| acc + usize::from(*x != initial_elem_value));
        Self {
            history_map,
            num_covered_map_indexes,
        }
    }

    /// Reset the map
    pub fn reset(&mut self) -> Result<(), Error> {
        let cnt = self.history_map.len();
        for i in 0..cnt {
            self.history_map[i] = T::default();
        }
        self.num_covered_map_indexes = 0;
        Ok(())
    }

    /// Reset the map with any value
    pub fn reset_with_value(&mut self, value: T) -> Result<(), Error> {
        let cnt = self.history_map.len();
        for i in 0..cnt {
            self.history_map[i] = value;
        }
        // assume that resetting the map should indicate no coverage,
        // regardless of value
        self.num_covered_map_indexes = 0;
        Ok(())
    }
}

/// The most common AFL-like feedback type
#[derive(Clone, Debug)]
pub struct MapFeedback<C, N, O, R, T> {
    /// New indexes observed in the last observation
    novelties: Option<Vec<usize>>,
    /// Name identifier of this instance
    name: Cow<'static, str>,
    /// Name identifier of the observer
    map_ref: Handle<C>,
    /// Name of the feedback as shown in the `UserStats`
    stats_name: Cow<'static, str>,
    /// Phantom Data of Reducer
    phantom: PhantomData<(C, N, O, R, T)>,
}

impl<C, N, O, R, S, T> Feedback<S> for MapFeedback<C, N, O, R, T>
where
    N: IsNovel<T>,
    O: MapObserver<Entry = T> + for<'it> AsIter<'it, Item = T>,
    R: Reducer<T>,
    S: State + HasNamedMetadata,
    T: Default + Copy + Serialize + for<'de> Deserialize<'de> + PartialEq + Debug + 'static,
    C: CanTrack + AsRef<O> + Observer<S>,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        // Initialize `MapFeedbackMetadata` with an empty vector and add it to the state.
        // The `MapFeedbackMetadata` would be resized on-demand in `is_interesting`
        state.add_named_metadata(&self.name, MapFeedbackMetadata::<T>::default());
        Ok(())
    }

    #[rustversion::nightly]
    default fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        Ok(self.is_interesting_default(state, manager, input, observers, exit_kind))
    }

    #[rustversion::not(nightly)]
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &<S as UsesInput>::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        Ok(self.is_interesting_default(state, manager, input, observers, exit_kind))
    }

    fn append_metadata<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
        EM: EventFirer<State = S>,
    {
        if let Some(novelties) = self.novelties.as_mut().map(core::mem::take) {
            let meta = MapNoveltiesMetadata::new(novelties);
            testcase.add_metadata(meta);
        }
        let observer = observers.get(&self.map_ref).unwrap().as_ref();
        let initial = observer.initial();
        let map_state = state
            .named_metadata_map_mut()
            .get_mut::<MapFeedbackMetadata<T>>(&self.name)
            .unwrap();
        let len = observer.len();
        if map_state.history_map.len() < len {
            map_state.history_map.resize(len, observer.initial());
        }

        let history_map = &mut map_state.history_map;
        if C::INDICES {
            let mut indices = Vec::new();

            for (i, value) in observer
                .as_iter()
                .map(|x| *x)
                .enumerate()
                .filter(|(_, value)| *value != initial)
            {
                if history_map[i] == initial {
                    map_state.num_covered_map_indexes += 1;
                }
                history_map[i] = R::reduce(history_map[i], value);
                indices.push(i);
            }
            let meta = MapIndexesMetadata::new(indices);
            testcase.add_metadata(meta);
        } else {
            for (i, value) in observer
                .as_iter()
                .map(|x| *x)
                .enumerate()
                .filter(|(_, value)| *value != initial)
            {
                if history_map[i] == initial {
                    map_state.num_covered_map_indexes += 1;
                }
                history_map[i] = R::reduce(history_map[i], value);
            }
        }

        debug_assert!(
            history_map
                .iter()
                .fold(0, |acc, x| acc + usize::from(*x != initial))
                == map_state.num_covered_map_indexes,
            "history_map had {} filled, but map_state.num_covered_map_indexes was {}",
            history_map
                .iter()
                .fold(0, |acc, x| acc + usize::from(*x != initial)),
            map_state.num_covered_map_indexes,
        );

        // at this point you are executing this code, the testcase is always interesting
        let covered = map_state.num_covered_map_indexes;
        let len = history_map.len();
        // opt: if not tracking optimisations, we technically don't show the *current* history
        // map but the *last* history map; this is better than walking over and allocating
        // unnecessarily
        manager.fire(
            state,
            Event::UpdateUserStats {
                name: self.stats_name.clone(),
                value: UserStats::new(
                    UserStatsValue::Ratio(covered as u64, len as u64),
                    AggregatorOps::Avg,
                ),
                phantom: PhantomData,
            },
        )?;

        Ok(())
    }
}

/// Specialize for the common coverage map size, maximization of u8s
#[rustversion::nightly]
impl<C, O, S> Feedback<S> for MapFeedback<C, DifferentIsNovel, O, MaxReducer, u8>
where
    O: MapObserver<Entry = u8> + for<'a> AsSlice<'a, Entry = u8> + for<'a> AsIter<'a, Item = u8>,
    S: State + HasNamedMetadata,
    C: CanTrack + AsRef<O> + Observer<S>,
{
    #[allow(clippy::wrong_self_convention)]
    #[allow(clippy::needless_range_loop)]
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        // 128 bits vectors
        type VectorType = core::simd::u8x16;

        let mut interesting = false;
        // TODO Replace with match_name_type when stable
        let observer = observers.get(&self.map_ref).unwrap().as_ref();

        let map_state = state
            .named_metadata_map_mut()
            .get_mut::<MapFeedbackMetadata<u8>>(&self.name)
            .unwrap();
        let size = observer.usable_count();
        let len = observer.len();
        if map_state.history_map.len() < len {
            map_state.history_map.resize(len, u8::default());
        }

        let map = observer.as_slice();
        debug_assert!(map.len() >= size);

        let history_map = map_state.history_map.as_slice();

        // Non vector implementation for reference
        /*for (i, history) in history_map.iter_mut().enumerate() {
            let item = map[i];
            let reduced = MaxReducer::reduce(*history, item);
            if DifferentIsNovel::is_novel(*history, reduced) {
                *history = reduced;
                interesting = true;
                if self.novelties.is_some() {
                    self.novelties.as_mut().unwrap().push(i);
                }
            }
        }*/

        let steps = size / VectorType::LEN;
        let left = size % VectorType::LEN;

        if let Some(novelties) = self.novelties.as_mut() {
            novelties.clear();
            for step in 0..steps {
                let i = step * VectorType::LEN;
                let history = VectorType::from_slice(&history_map[i..]);
                let items = VectorType::from_slice(&map[i..]);

                if items.simd_max(history) != history {
                    interesting = true;
                    unsafe {
                        for j in i..(i + VectorType::LEN) {
                            let item = *map.get_unchecked(j);
                            if item > *history_map.get_unchecked(j) {
                                novelties.push(j);
                            }
                        }
                    }
                }
            }

            for j in (size - left)..size {
                unsafe {
                    let item = *map.get_unchecked(j);
                    if item > *history_map.get_unchecked(j) {
                        interesting = true;
                        novelties.push(j);
                    }
                }
            }
        } else {
            for step in 0..steps {
                let i = step * VectorType::LEN;
                let history = VectorType::from_slice(&history_map[i..]);
                let items = VectorType::from_slice(&map[i..]);

                if items.simd_max(history) != history {
                    interesting = true;
                    break;
                }
            }

            if !interesting {
                for j in (size - left)..size {
                    unsafe {
                        let item = *map.get_unchecked(j);
                        if item > *history_map.get_unchecked(j) {
                            interesting = true;
                            break;
                        }
                    }
                }
            }
        }

        Ok(interesting)
    }
}

impl<C, N, O, R, T> Named for MapFeedback<C, N, O, R, T> {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<C, N, O, R, T> HasObserverHandle for MapFeedback<C, N, O, R, T>
where
    O: Named,
    C: AsRef<O>,
{
    type Observer = C;

    #[inline]
    fn observer_handle(&self) -> &Handle<C> {
        &self.map_ref
    }
}

#[allow(clippy::ptr_arg)]
fn create_stats_name(name: &Cow<'static, str>) -> Cow<'static, str> {
    if name.chars().all(char::is_lowercase) {
        name.clone()
    } else {
        name.to_lowercase().into()
    }
}

impl<C, N, O, R, T> MapFeedback<C, N, O, R, T>
where
    T: PartialEq + Default + Copy + 'static + Serialize + DeserializeOwned + Debug,
    R: Reducer<T>,
    O: MapObserver<Entry = T>,
    for<'it> O: AsIter<'it, Item = T>,
    N: IsNovel<T>,
    C: CanTrack + AsRef<O> + Named,
{
    /// Create new `MapFeedback`
    #[must_use]
    pub fn new(map_observer: &C) -> Self {
        Self {
            novelties: if C::NOVELTIES { Some(vec![]) } else { None },
            name: map_observer.name().clone(),
            map_ref: map_observer.handle(),
            stats_name: create_stats_name(map_observer.name()),
            phantom: PhantomData,
        }
    }

    /// Creating a new `MapFeedback` with a specific name. This is usefully whenever the same
    /// feedback is needed twice, but with a different history. Using `new()` always results in the
    /// same name and therefore also the same history.
    #[must_use]
    pub fn with_name(name: &'static str, map_observer: &C) -> Self {
        let name = Cow::from(name);
        Self {
            novelties: if C::NOVELTIES { Some(vec![]) } else { None },
            map_ref: map_observer.handle(),
            stats_name: create_stats_name(&name),
            name,
            phantom: PhantomData,
        }
    }

    #[allow(clippy::wrong_self_convention)]
    #[allow(clippy::needless_range_loop)]
    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn is_interesting_default<EM, S, OT>(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> bool
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
        S: UsesInput + HasNamedMetadata,
    {
        let mut interesting = false;
        // TODO Replace with match_name_type when stable
        let observer = observers.get(&self.map_ref).unwrap().as_ref();

        let map_state = state
            .named_metadata_map_mut()
            .get_mut::<MapFeedbackMetadata<T>>(&self.name)
            .unwrap();
        let len = observer.len();
        if map_state.history_map.len() < len {
            map_state.history_map.resize(len, observer.initial());
        }

        let history_map = map_state.history_map.as_slice();

        let initial = observer.initial();

        if let Some(novelties) = self.novelties.as_mut() {
            novelties.clear();
            for (i, item) in observer
                .as_iter()
                .map(|x| *x)
                .enumerate()
                .filter(|(_, item)| *item != initial)
            {
                let existing = unsafe { *history_map.get_unchecked(i) };
                let reduced = R::reduce(existing, item);
                if N::is_novel(existing, reduced) {
                    interesting = true;
                    novelties.push(i);
                }
            }
        } else {
            for (i, item) in observer
                .as_iter()
                .map(|x| *x)
                .enumerate()
                .filter(|(_, item)| *item != initial)
            {
                let existing = unsafe { *history_map.get_unchecked(i) };
                let reduced = R::reduce(existing, item);
                if N::is_novel(existing, reduced) {
                    interesting = true;
                    break;
                }
            }
        }

        interesting
    }
}

#[cfg(test)]
mod tests {
    use crate::feedbacks::{AllIsNovel, IsNovel, NextPow2IsNovel};

    #[test]
    fn test_map_is_novel() {
        // sanity check
        assert!(AllIsNovel::is_novel(0_u8, 0));

        assert!(!NextPow2IsNovel::is_novel(0_u8, 0));
        assert!(NextPow2IsNovel::is_novel(0_u8, 1));
        assert!(!NextPow2IsNovel::is_novel(1_u8, 1));
        assert!(NextPow2IsNovel::is_novel(1_u8, 2));
        assert!(!NextPow2IsNovel::is_novel(2_u8, 2));
        assert!(!NextPow2IsNovel::is_novel(2_u8, 3));
        assert!(NextPow2IsNovel::is_novel(2_u8, 4));
        assert!(!NextPow2IsNovel::is_novel(128_u8, 128));
        assert!(!NextPow2IsNovel::is_novel(129_u8, 128));
        assert!(NextPow2IsNovel::is_novel(128_u8, 255));
        assert!(!NextPow2IsNovel::is_novel(255_u8, 128));
        assert!(NextPow2IsNovel::is_novel(254_u8, 255));
        assert!(!NextPow2IsNovel::is_novel(255_u8, 255));
    }
}
