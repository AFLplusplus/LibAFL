use std::{
    borrow::Cow,
    fmt::Debug,
    hash::{Hash, Hasher},
    ops::Deref,
};

use ahash::AHasher;
use libafl::{
    executors::ExitKind,
    inputs::UsesInput,
    observers::{MapObserver, Observer, TimeObserver},
    state::UsesState,
    Error,
};
use libafl_bolts::{AsIter, HasLen, Named};
use num_traits::Bounded;
use serde::{Deserialize, Serialize};

static INITIAL_SIZE: usize = usize::MAX;
static INITIAL_TIME: u64 = u64::MAX;

pub trait ValueObserver: for<'de> Deserialize<'de> + Serialize + Debug + Named {
    type ValueType: Bounded
        + Default
        + Copy
        + Serialize
        + for<'de> Deserialize<'de>
        + PartialEq
        + Hash
        + Debug
        + 'static;

    fn value(&self) -> &Self::ValueType;

    fn default_value(&self) -> &Self::ValueType;
}

#[derive(Deserialize, Serialize, Debug)]
pub struct MappedEdgeMapObserver<M, O> {
    inner: M,
    name: Cow<'static, str>,
    value_observer: O,
}

impl<M, O> MappedEdgeMapObserver<M, O>
where
    M: MapObserver,
    O: ValueObserver,
{
    pub fn new(obs: M, value_obs: O) -> Self {
        Self {
            name: Cow::from(format!("{}_{}", value_obs.name(), obs.name())),
            inner: obs,
            value_observer: value_obs,
        }
    }
}

impl<M, O> AsRef<Self> for MappedEdgeMapObserver<M, O> {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<M, O> AsMut<Self> for MappedEdgeMapObserver<M, O> {
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl<M, O> HasLen for MappedEdgeMapObserver<M, O>
where
    M: HasLen,
{
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<M, O> Named for MappedEdgeMapObserver<M, O> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<M, O> Hash for MappedEdgeMapObserver<M, O>
where
    M: MapObserver + for<'it> AsIter<'it, Item = M::Entry>,
    O: ValueObserver,
{
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        let initial = self.inner.initial();
        for e in self.inner.as_iter() {
            if *e == initial {
                self.value_observer.default_value().hash(hasher);
            } else {
                self.value_observer.value().hash(hasher);
            }
        }
    }
}

impl<M, O> MapObserver for MappedEdgeMapObserver<M, O>
where
    M: MapObserver + for<'it> AsIter<'it, Item = M::Entry>,
    O: ValueObserver,
{
    type Entry = O::ValueType;

    fn get(&self, idx: usize) -> Self::Entry {
        let initial = self.inner.initial();
        if self.inner.get(idx) == initial {
            *self.value_observer.default_value()
        } else {
            *self.value_observer.value()
        }
    }

    fn set(&mut self, _idx: usize, _val: Self::Entry) {
        unimplemented!("Impossible to implement for a proxy map.")
    }

    fn usable_count(&self) -> usize {
        self.inner.usable_count()
    }

    fn count_bytes(&self) -> u64 {
        self.inner.count_bytes()
    }

    fn hash_simple(&self) -> u64 {
        let mut hasher = AHasher::default();
        self.hash(&mut hasher);
        hasher.finish()
    }

    fn initial(&self) -> Self::Entry {
        *self.value_observer.default_value()
    }

    fn reset_map(&mut self) -> Result<(), Error> {
        self.inner.reset_map()
    }

    fn to_vec(&self) -> Vec<Self::Entry> {
        let initial = self.inner.initial();
        let default = *self.value_observer.default_value();
        let value = *self.value_observer.value();
        self.inner
            .as_iter()
            .map(|e| if *e == initial { default } else { value })
            .collect()
    }

    fn how_many_set(&self, indexes: &[usize]) -> usize {
        self.inner.how_many_set(indexes)
    }
}

impl<M, O> UsesState for MappedEdgeMapObserver<M, O>
where
    M: UsesState,
{
    type State = M::State;
}

impl<M, O, S> Observer<S::Input, S> for MappedEdgeMapObserver<M, O>
where
    M: Observer<S::Input, S> + Debug,
    O: Observer<S::Input, S> + Debug,
    S: UsesInput,
{
    fn pre_exec(&mut self, state: &mut S, input: &S::Input) -> Result<(), Error> {
        self.inner.pre_exec(state, input)?;
        self.value_observer.pre_exec(state, input)
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.inner.post_exec(state, input, exit_kind)?;
        self.value_observer.post_exec(state, input, exit_kind)
    }
}

pub struct MappedEdgeMapIter<'it, I, O, T> {
    inner: I,
    initial: T,
    value_obs: &'it O,
}

impl<'it, I, O, T> MappedEdgeMapIter<'it, I, O, T> {
    fn new(iter: I, initial: T, value_obs: &'it O) -> Self {
        Self {
            inner: iter,
            initial,
            value_obs,
        }
    }
}

impl<'it, I, O, R, T> Iterator for MappedEdgeMapIter<'it, I, O, T>
where
    I: Iterator<Item = R>,
    R: Deref<Target = T>,
    T: PartialEq + 'it,
    O: ValueObserver,
{
    type Item = &'it O::ValueType;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|e| {
            (*e == self.initial)
                .then(|| self.value_obs.default_value())
                .unwrap_or_else(|| self.value_obs.value())
        })
    }
}

impl<'it, M, O> AsIter<'it> for MappedEdgeMapObserver<M, O>
where
    M: MapObserver + for<'a> AsIter<'a, Item = M::Entry>,
    M::Entry: 'it,
    O: ValueObserver + 'it,
{
    type Item = O::ValueType;
    type Ref = &'it Self::Item;
    type IntoIter = MappedEdgeMapIter<'it, <M as AsIter<'it>>::IntoIter, O, M::Entry>;

    fn as_iter(&'it self) -> Self::IntoIter {
        let iter = self.inner.as_iter();
        let initial = self.inner.initial();
        MappedEdgeMapIter::new(iter, initial, &self.value_observer)
    }
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug, Default)]
pub struct SizeValueObserver {
    size: usize,
}

impl ValueObserver for SizeValueObserver {
    type ValueType = usize;

    fn value(&self) -> &Self::ValueType {
        &self.size
    }

    fn default_value(&self) -> &Self::ValueType {
        &INITIAL_SIZE
    }
}

impl Named for SizeValueObserver {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("size");
        &NAME
    }
}

impl<S> Observer<S::Input, S> for SizeValueObserver
where
    S: UsesInput,
    S::Input: HasLen,
{
    fn pre_exec(&mut self, _state: &mut S, input: &S::Input) -> Result<(), Error> {
        self.size = input.len();
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TimeValueObserver {
    time: u64,
    time_obs: TimeObserver,
}

impl TimeValueObserver {
    pub fn new(time_obs: TimeObserver) -> Self {
        Self {
            time: INITIAL_TIME,
            time_obs,
        }
    }
}

impl ValueObserver for TimeValueObserver {
    type ValueType = u64;

    fn value(&self) -> &Self::ValueType {
        &self.time
    }

    fn default_value(&self) -> &Self::ValueType {
        &INITIAL_TIME
    }
}

impl Named for TimeValueObserver {
    fn name(&self) -> &Cow<'static, str> {
        self.time_obs.name()
    }
}

impl<S> Observer<S::Input, S> for TimeValueObserver
where
    S: UsesInput,
{
    fn pre_exec(&mut self, state: &mut S, input: &S::Input) -> Result<(), Error> {
        self.time_obs.pre_exec(state, input)
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.time_obs.post_exec(state, input, exit_kind)?;
        self.time = self
            .time_obs
            .last_runtime()
            .as_ref()
            .map_or(INITIAL_TIME, |duration| {
                u64::try_from(duration.as_micros()).unwrap_or(INITIAL_TIME)
            });
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SizeTimeValueObserver {
    value: u64,
    size_obs: SizeValueObserver,
    time_obs: TimeValueObserver,
}

impl SizeTimeValueObserver {
    pub fn new(time_obs: TimeObserver) -> Self {
        Self {
            value: INITIAL_TIME,
            size_obs: SizeValueObserver::default(),
            time_obs: TimeValueObserver::new(time_obs),
        }
    }
}

impl ValueObserver for SizeTimeValueObserver {
    type ValueType = u64;

    fn value(&self) -> &Self::ValueType {
        &self.value
    }

    fn default_value(&self) -> &Self::ValueType {
        &INITIAL_TIME
    }
}

impl Named for SizeTimeValueObserver {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("size_time");
        &NAME
    }
}

impl<S> Observer<S::Input, S> for SizeTimeValueObserver
where
    S: UsesInput,
    S::Input: HasLen,
{
    fn pre_exec(&mut self, state: &mut S, input: &S::Input) -> Result<(), Error> {
        self.size_obs.pre_exec(state, input)?;
        self.time_obs.pre_exec(state, input)
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.time_obs.post_exec(state, input, exit_kind)?;
        self.size_obs.post_exec(state, input, exit_kind)?;
        self.value = self
            .time_obs
            .value()
            .saturating_mul(*self.size_obs.value() as u64);
        Ok(())
    }
}
