use alloc::borrow::Cow;
use core::{fmt::Debug, hash::Hash};

use hashbrown::HashSet;
use libafl_bolts::{
    Error, HasRefCnt, Named,
    tuples::{Handle, Handled, MatchName, MatchNameRef},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    HasNamedMetadata,
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
    observers::ListObserver,
    std::fs::File,
    std::io::Write,
    std::path::Path,
};

/// The metadata to remember past observed value
#[derive(Debug, Serialize, Deserialize)]
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

impl<T> Default for ListFeedbackMetadata<T> {
    fn default() -> Self {
        Self::new()
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
#[derive(Debug, Clone)]
pub struct ListFeedback<T> {
    observer_handle: Handle<ListObserver<T>>,
    novelty: HashSet<T>,
}

libafl_bolts::impl_serdeany!(
    ListFeedbackMetadata<T: Debug + 'static + Serialize + DeserializeOwned + Eq + Hash>,
    <u8>,<u16>,<u32>,<u64>,<i8>,<i16>,<i32>,<i64>,<bool>,<char>,<usize>
);

impl<T> ListFeedback<T>
where
    T: Debug + Eq + Hash + for<'a> Deserialize<'a> + Serialize + 'static + Copy,
{
    fn has_interesting_list_observer_feedback<OT, S>(
        &mut self,
        state: &mut S,
        observers: &OT,
    ) -> bool
    where
        OT: MatchName,
        S: HasNamedMetadata,
    {
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
        !self.novelty.is_empty()
    }

    fn append_list_observer_metadata<S: HasNamedMetadata>(&mut self, state: &mut S) {
        let history_set = state
            .named_metadata_map_mut()
            .get_mut::<ListFeedbackMetadata<T>>(self.name())
            .unwrap();

        for v in &self.novelty {
            history_set.set.insert(*v);
        }
    }
}

impl<S, T> StateInitializer<S> for ListFeedback<T>
where
    S: HasNamedMetadata,
    T: Debug + Eq + Hash + for<'a> Deserialize<'a> + Serialize + Default + Copy + 'static,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        state.add_named_metadata_checked(self.name(), ListFeedbackMetadata::<T>::default())?;
        Ok(())
    }
}

impl<EM, I, OT, S, T> Feedback<EM, I, OT, S> for ListFeedback<T>
where
    OT: MatchName,
    S: HasNamedMetadata,
    T: Debug + Eq + Hash + for<'a> Deserialize<'a> + Serialize + Default + Copy + 'static,
{
    fn is_interesting(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        Ok(self.has_interesting_list_observer_feedback(state, observers))
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
        self.append_list_observer_metadata(state);
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

/// Consider interesting a testcase if the list in `ListObserver` is not empty.
/// Modified version of [[`ListFeedback`]] that expects a [[`ListObserver`]]
/// containing addresses and will write any newly observed address to
/// a file (see [[`ListDumpFeedback::new`]])
#[derive(Debug)]
pub struct ListDumpFeedback {
    observer_handle: Handle<ListObserver<u64>>,
    novelty: HashSet<u64>,
    file: File,
}

impl ListDumpFeedback {
    fn has_interesting_list_observer_feedback<OT, S>(
        &mut self,
        state: &mut S,
        observers: &OT,
    ) -> bool
    where
        OT: MatchName,
        S: HasNamedMetadata,
    {
        let observer = observers.get(&self.observer_handle).unwrap();
        // TODO register the list content in a testcase metadata
        self.novelty.clear();
        // can't fail
        let history_set = state
            .named_metadata_map_mut()
            .get_mut::<ListFeedbackMetadata<u64>>(self.name())
            .unwrap();
        for v in observer.list() {
            if !history_set.set.contains(v) {
                self.novelty.insert(*v);
            }
        }
        if !self.novelty.is_empty() {
            for line in &self.novelty {
                self.file
                    .write_all(format!("0x{line:x}\n").as_bytes())
                    .unwrap();
            }
            return true;
        }
        false
    }

    fn append_list_observer_metadata<S: HasNamedMetadata>(&mut self, state: &mut S) {
        let history_set = state
            .named_metadata_map_mut()
            .get_mut::<ListFeedbackMetadata<u64>>(self.name())
            .unwrap();

        for v in &self.novelty {
            history_set.set.insert(*v);
        }
    }
}

impl<S> StateInitializer<S> for ListDumpFeedback
where
    S: HasNamedMetadata,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        state.add_named_metadata_checked(self.name(), ListFeedbackMetadata::<u64>::default())?;
        Ok(())
    }
}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for ListDumpFeedback
where
    OT: MatchName,
    S: HasNamedMetadata,
{
    fn is_interesting(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        Ok(self.has_interesting_list_observer_feedback(state, observers))
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
        self.append_list_observer_metadata(state);
        Ok(())
    }
}

impl Named for ListDumpFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        self.observer_handle.name()
    }
}

impl ListDumpFeedback {
    /// Creates a new [`ListDumpFeedback`], deciding if the given [`ListObserver`] value of a run is interesting.
    /// Dump newly observed addresses to `path`
    #[must_use]
    pub fn new<P: AsRef<Path>>(observer: &ListObserver<u64>, path: P) -> Self {
        let file = File::create(path).unwrap();

        Self {
            observer_handle: observer.handle(),
            novelty: HashSet::new(),
            file,
        }
    }
}
