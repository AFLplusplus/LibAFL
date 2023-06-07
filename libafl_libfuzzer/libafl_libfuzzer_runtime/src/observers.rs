use std::{
    fmt::{Debug, Formatter},
    hash::{BuildHasher, Hasher},
    iter::Map,
    marker::PhantomData,
};

use ahash::{AHasher, RandomState};
use libafl::{
    bolts::{tuples::Named, AsIter, HasLen},
    inputs::UsesInput,
    observers::{MapObserver, Observer},
    state::UsesState,
    Error,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

static INITIAL: usize = usize::MAX;

#[derive(Deserialize, Serialize, Debug)]
pub struct SizeEdgeMapObserver<M, T> {
    inner: M,
    name: String,
    size: usize,
    phantom: PhantomData<T>,
}

impl<M, T> SizeEdgeMapObserver<M, T>
where
    M: MapObserver<Entry = T>,
{
    pub fn new(obs: M) -> Self {
        Self {
            name: format!("size_{}", obs.name()),
            inner: obs,
            size: INITIAL,
            phantom: PhantomData,
        }
    }
}

impl<M, T> HasLen for SizeEdgeMapObserver<M, T>
where
    M: HasLen,
{
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<M, T> Named for SizeEdgeMapObserver<M, T> {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<M, T> MapObserver for SizeEdgeMapObserver<M, T>
where
    M: MapObserver<Entry = T> + for<'it> AsIter<'it, Item = T>,
    T: Default + Copy + Serialize + for<'de> Deserialize<'de> + PartialEq + Debug + 'static,
{
    type Entry = usize;

    fn get(&self, idx: usize) -> &Self::Entry {
        let initial = self.inner.initial();
        if *self.inner.get(idx) == initial {
            &INITIAL
        } else {
            &self.size
        }
    }

    fn get_mut(&mut self, idx: usize) -> &mut Self::Entry {
        unimplemented!("Impossible to implement for a proxy map.")
    }

    fn usable_count(&self) -> usize {
        self.inner.usable_count()
    }

    fn count_bytes(&self) -> u64 {
        self.inner.count_bytes()
    }

    fn hash(&self) -> u64 {
        let mut hasher = AHasher::default();
        let initial = self.inner.initial();
        for e in self.inner.as_iter() {
            if *e == initial {
                hasher.write_usize(INITIAL);
            } else {
                hasher.write_usize(self.size);
            }
        }
        hasher.finish()
    }

    fn initial(&self) -> Self::Entry {
        INITIAL
    }

    fn reset_map(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn to_vec(&self) -> Vec<Self::Entry> {
        let initial = self.inner.initial();
        self.inner
            .as_iter()
            .map(|&e| (e == initial).then_some(INITIAL).unwrap_or(self.size))
            .collect()
    }

    fn how_many_set(&self, indexes: &[usize]) -> usize {
        self.inner.how_many_set(indexes)
    }
}

impl<M, T> UsesState for SizeEdgeMapObserver<M, T>
where
    M: UsesState,
{
    type State = M::State;
}

impl<M, S, T> Observer<S> for SizeEdgeMapObserver<M, T>
where
    M: Observer<S> + Debug,
    S: UsesInput,
    T: Debug,
{
    // normally, you would reset the map here
    // in our case, we know that the map has already been reset by the other map observer
}

pub struct SizeEdgeMapIter<'it, I, T> {
    inner: I,
    initial: T,
    value: &'it usize,
    phantom: PhantomData<T>,
}

impl<'it, I, T> SizeEdgeMapIter<'it, I, T> {
    fn new(iter: I, initial: T, value: &'it usize) -> Self {
        Self {
            inner: iter,
            initial,
            value,
            phantom: PhantomData,
        }
    }
}

impl<'it, I, T> Iterator for SizeEdgeMapIter<'it, I, T>
where
    I: Iterator<Item = &'it T>,
    T: Default + Copy + Serialize + for<'de> Deserialize<'de> + PartialEq + Debug + 'static,
{
    type Item = &'it usize;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|e| {
            (*e == self.initial)
                .then_some(&INITIAL)
                .unwrap_or(self.value)
        })
    }
}

impl<'it, M, T> AsIter<'it> for SizeEdgeMapObserver<M, T>
where
    M: MapObserver<Entry = T> + for<'a> AsIter<'a, Item = T>,
    T: Default + Copy + Serialize + for<'de> Deserialize<'de> + PartialEq + Debug + 'static,
{
    type Item = usize;
    type IntoIter = SizeEdgeMapIter<'it, <M as AsIter<'it>>::IntoIter, T>;

    fn as_iter(&'it self) -> Self::IntoIter {
        let iter = self.inner.as_iter();
        let initial = self.inner.initial();
        SizeEdgeMapIter::new(iter, initial, &self.size)
    }
}
