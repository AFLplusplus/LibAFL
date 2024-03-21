use alloc::string::{String, ToString};
use core::{fmt::Debug, hash::Hash, marker::PhantomData};

use hashbrown::HashSet;
use libafl_bolts::{Error, HasRefCnt, Named};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    events::EventFirer,
    executors::ExitKind,
    feedbacks::Feedback,
    observers::{ListObserver, ObserversTuple},
    state::{HasNamedMetadata, State},
};

/// The metadata to remember past observed value
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "T: DeserializeOwned")]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)]
pub struct ListFeedbackMetadata<T>
where
    T: Default + Copy + 'static + Serialize + Eq + Hash,
{
    /// Contains the information of past observed set of values.
    pub set: HashSet<T>,
    /// A refcount used to know when we can remove this metadata
    pub tcref: isize,
}

impl<T> ListFeedbackMetadata<T>
where
    T: Default + Copy + 'static + Serialize + Eq + Hash,
{
    /// The constructor
    #[must_use]
    pub fn new() -> Self {
        Self {
            set: HashSet::<T>::new(),
            tcref: 0,
        }
    }

    /// Reset the inner hashset
    pub fn reset(&mut self) -> Result<(), Error> {
        self.set.clear();
        Ok(())
    }
}

impl<T> HasRefCnt for ListFeedbackMetadata<T>
where
    T: Default + Copy + 'static + Serialize + Eq + Hash,
{
    fn refcnt(&self) -> isize {
        self.tcref
    }

    fn refcnt_mut(&mut self) -> &mut isize {
        &mut self.tcref
    }
}

/// Consider interesting a testcase if the list in `ListObserver` is not empty.
#[derive(Clone, Debug)]
pub struct ListFeedback<T>
where
    T: Hash + Eq,
{
    name: String,
    observer_name: String,
    novelty: HashSet<T>,
    phantom: PhantomData<T>,
}

libafl_bolts::impl_serdeany!(
    ListFeedbackMetadata<T: Debug + Default + Copy + 'static + Serialize + DeserializeOwned + Eq + Hash>,
    <u8>,<u16>,<u32>,<u64>,<i8>,<i16>,<i32>,<i64>,<bool>,<char>,<usize>
);

impl<S, T> Feedback<S> for ListFeedback<T>
where
    S: State + HasNamedMetadata,
    T: Debug + Serialize + Hash + Eq + DeserializeOwned + Default + Copy + 'static,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        // eprintln!("self.name {:#?}", &self.name);
        state.add_named_metadata(&self.name, ListFeedbackMetadata::<T>::default());
        Ok(())
    }
    #[allow(clippy::wrong_self_convention)]
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
        // TODO Replace with match_name_type when stable
        let observer = observers
            .match_name::<ListObserver<T>>(&self.observer_name)
            .unwrap();
        // TODO register the list content in a testcase metadata
        self.novelty.clear();
        // can't fail
        let history_set = state
            .named_metadata_map_mut()
            .get_mut::<ListFeedbackMetadata<T>>(&self.name)
            .unwrap();
        for v in observer.list() {
            if !history_set.set.contains(v) {
                self.novelty.insert(*v);
            }
        }
        Ok(!self.novelty.is_empty())
    }

    fn append_metadata<EM, OT>(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        _testcase: &mut crate::corpus::Testcase<<S>::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
        EM: EventFirer<State = S>,
    {
        let history_set = state
            .named_metadata_map_mut()
            .get_mut::<ListFeedbackMetadata<T>>(&self.name)
            .unwrap();

        for v in &self.novelty {
            history_set.set.insert(*v);
        }
        Ok(())
    }
}

impl<T> Named for ListFeedback<T>
where
    T: Debug + Serialize + Hash + Eq + DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<T> ListFeedback<T>
where
    T: Debug + Serialize + Hash + Eq + DeserializeOwned,
{
    /// Creates a new [`ListFeedback`], deciding if the given [`ListObserver`] value of a run is interesting.
    #[must_use]
    pub fn new(observer: &ListObserver<T>) -> Self {
        Self {
            name: observer.name().to_string(),
            observer_name: observer.name().to_string(),
            novelty: HashSet::<T>::new(),
            phantom: PhantomData,
        }
    }
}
