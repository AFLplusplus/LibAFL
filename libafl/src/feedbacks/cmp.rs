use alloc::string::{String, ToString};
use core::marker::PhantomData;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::{tuples::Named, AsSlice},
    executors::ExitKind,
    feedbacks::Feedback,
    inputs::Input,
    observers::{CmpMap, CmpObserver, CmpValues, ObserversTuple},
    state::HasMetadata,
    Error,
};

/// A state metadata holding a list of values logged from comparisons
#[derive(Serialize, Deserialize)]
pub struct CmpValuesMetadata {
    /// A `list` of values.
    pub list: Vec<CmpValues>,
}

crate::impl_serdeany!(CmpValuesMetadata);

impl AsSlice<CmpValues> for CmpValuesMetadata {
    /// Convert to a slice
    #[must_use]
    fn as_slice(&self) -> &[CmpValues] {
        self.list.as_slice()
    }
}

impl CmpValuesMetadata {
    /// Creates a new [`struct@CmpValuesMetadata`]
    #[must_use]
    pub fn new() -> Self {
        Self { list: vec![] }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CmpFeedback<CM, CO>
where
    CO: CmpObserver<CM>,
    CM: CmpMap,
{
    name: String,
    phantom: PhantomData<(CM, CO)>,
}

impl<CM, CO, I, S> Feedback<I, S> for CmpFeedback<CM, CO>
where
    I: Input,
    CO: CmpObserver<CM>,
    CM: CmpMap,
    S: HasMetadata,
{
    fn is_interesting<OT>(
        &mut self,
        state: &mut S,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple,
    {
        if state.metadata().get::<CmpValuesMetadata>().is_none() {
            state.add_metadata(CmpValuesMetadata::new());
        }
        let meta = state.metadata_mut().get_mut::<CmpValuesMetadata>().unwrap();
        meta.list.clear();
        // TODO Replace with match_name_type when stable
        let observer = observers.match_name::<CO>(self.name()).unwrap();
        let count = observer.usable_count();
        for i in 0..count {
            let execs = observer.map().usable_executions_for(i);
            if execs > 0 {
                // Recongize loops and discard
                // TODO
                for j in 0..execs {
                    meta.list.push(observer.map().values_of(i, j));
                }
            }
        }
        Ok(false)
    }
}

impl<CM, CO> Named for CmpFeedback<CM, CO>
where
    CO: CmpObserver<CM>,
    CM: CmpMap,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<CM, CO> CmpFeedback<CM, CO>
where
    CO: CmpObserver<CM>,
    CM: CmpMap,
{
    /// Creates a new [`CmpFeedback`]
    #[must_use]
    pub fn with_name(name: &'static str) -> Self {
        Self {
            name: name.to_string(),
            phantom: PhantomData,
        }
    }

    /// Creates a new [`CmpFeedback`]
    #[must_use]
    pub fn new(observer: &CO) -> Self {
        Self {
            name: observer.name().to_string(),
            phantom: PhantomData,
        }
    }
}
