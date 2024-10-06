use alloc::borrow::Cow;
use core::{fmt::Debug, hash::Hash};

use hashbrown::HashSet;
use libafl_bolts::{
    tuples::{Handle, Handled, MatchName, MatchNameRef},
    Error, HasRefCnt, Named,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
    observers::ListObserver,
    HasNamedMetadata,
};

/// The metadata to remember past observed value
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "T: Eq + Hash + for<'a> Deserialize<'a> + Serialize")]
pub struct ListFeedbackMetadata<T> {
    /// Contains the information of past observed set of values.
    pub set: HashSet<T>,
    /// A refcount used to know when we can remove this metadata
    pub tcref: isize,
}

impl<T> ListFeedbackMetadata<T> {
    /// The constructor
    #[must_use]
    pub fn new() -> Self {
        Self {
            set: HashSet::new(),
            tcref: 0,
        }
    }

    /// Reset the inner hashset
    pub fn reset(&mut self) -> Result<(), Error> {
        self.set.clear();
        Ok(())
    }
}

impl<T> HasRefCnt for ListFeedbackMetadata<T> {
    fn refcnt(&self) -> isize {
        self.tcref
    }

    fn refcnt_mut(&mut self) -> &mut isize {
        &mut self.tcref
    }
}

/// Consider interesting a testcase if the list in `ListObserver` is not empty.
#[derive(Clone, Debug)]
pub struct ListFeedback<T> {
    observer_handle: Handle<ListObserver<T>>,
    novelty: HashSet<T>,
}

libafl_bolts::impl_serdeany!(
    ListFeedbackMetadata<T: Debug + Default + Copy + 'static + Serialize + DeserializeOwned + Eq + Hash>,
    <u8>,<u16>,<u32>,<u64>,<i8>,<i16>,<i32>,<i64>,<bool>,<char>,<usize>
);

impl<S, T> StateInitializer<S> for ListFeedback<T>
where
    S: HasNamedMetadata,
    T: Debug + Serialize + Hash + Eq + DeserializeOwned + Default + Copy + 'static,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        state.add_named_metadata(self.name(), ListFeedbackMetadata::<T>::default());
        Ok(())
    }
}

impl<EM, I, OT, S, T> Feedback<EM, I, OT, S> for ListFeedback<T>
where
    OT: MatchName,
    S: HasNamedMetadata,
    T: Debug + Serialize + Hash + Eq + DeserializeOwned + Default + Copy + 'static,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        let observer = observers.get(&self.observer_handle).unwrap();
        // TODO register the list content in a testcase metadata
        self.novelty.clear();
        // can't fail
        let history_set = state
            .named_metadata_map_mut()
            .get_mut::<ListFeedbackMetadata<T>>(self.name())
            .unwrap();
        for v in observer.list() {
            if !history_set.set.contains(v) {
                self.novelty.insert(*v);
            }
        }
        Ok(!self.novelty.is_empty())
    }

    #[cfg(feature = "track_hit_feedbacks")]
    fn last_result(&self) -> Result<bool, Error> {
        Ok(!self.novelty.is_empty())
    }

    fn append_metadata(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        _testcase: &mut crate::corpus::Testcase<I>,
    ) -> Result<(), Error> {
        let history_set = state
            .named_metadata_map_mut()
            .get_mut::<ListFeedbackMetadata<T>>(self.name())
            .unwrap();

        for v in &self.novelty {
            history_set.set.insert(*v);
        }
        Ok(())
    }
}

impl<T> Named for ListFeedback<T> {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        self.observer_handle.name()
    }
}

impl<T> ListFeedback<T> {
    /// Creates a new [`ListFeedback`], deciding if the given [`ListObserver`] value of a run is interesting.
    #[must_use]
    pub fn new(observer: &ListObserver<T>) -> Self {
        Self {
            observer_handle: observer.handle(),
            novelty: HashSet::new(),
        }
    }
}
