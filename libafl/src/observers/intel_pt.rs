use alloc::borrow::Cow;
use std::{
    sync::{Arc, Mutex},
    vec::Vec,
};

use libafl_bolts::Named;

use crate::{inputs::UsesInput, observers::Observer};

#[derive(Debug)]
pub struct IntelPTObserver {
    trace: Arc<Mutex<Vec<u8>>>,
}

impl Named for IntelPTObserver {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("IntelPTObserver")
    }
}

impl<S> Observer<S> for IntelPTObserver where S: UsesInput {}
