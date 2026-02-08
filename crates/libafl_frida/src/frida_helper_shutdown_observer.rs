use alloc::{borrow::Cow, rc::Rc, vec::Vec};
use core::{cell::RefCell, fmt};

use libafl::{
    executors::ExitKind,
    inputs::{HasTargetBytes, Input},
    observers::Observer,
};
use libafl_bolts::{ownedref::OwnedSlice, Error, Named};
use serde::{
    de::{self, Deserialize, Deserializer, MapAccess, Visitor},
    Serialize,
};

use crate::helper::{FridaInstrumentationHelper, FridaRuntimeTuple};

/// A trait for inputs that can be used with `FridaHelperObserver`
pub trait FridaHelperInput: Input {
    /// Get the target bytes for the input, if available
    fn target_bytes(&self) -> Option<OwnedSlice<'_, u8>>;
}

impl<T> FridaHelperInput for T
where
    T: Input + HasTargetBytes,
{
    fn target_bytes(&self) -> Option<OwnedSlice<'_, u8>> {
        Some(HasTargetBytes::target_bytes(self))
    }
}

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Serialize, Debug)]
/// An observer that shuts down the Frida helper upon crash
/// This is necessary as we don't want to keep the instrumentation around when processing the crash
pub struct FridaHelperObserver<'a, RT> {
    #[serde(skip)]
    helper: Rc<RefCell<FridaInstrumentationHelper<'a, RT>>>,
}

impl<'a, RT> FridaHelperObserver<'a, RT>
where
    RT: FridaRuntimeTuple + 'a,
{
    /// Creates a new [`FridaHelperObserver`] with the given name.
    #[must_use]
    pub fn new(helper: Rc<RefCell<FridaInstrumentationHelper<'a, RT>>>) -> Self {
        Self { helper }
    }
}

impl<'a, I, S, RT> Observer<I, S> for FridaHelperObserver<'a, RT>
where
    RT: FridaRuntimeTuple + 'a,
    I: FridaHelperInput,
{
    fn post_exec(&mut self, _state: &mut S, input: &I, exit_kind: &ExitKind) -> Result<(), Error> {
        if *exit_kind == ExitKind::Crash {
            // Custom implementation logic for `FridaInProcessExecutor`
            log::error!("Custom post_exec called for FridaInProcessExecutorHelper");
            // Add any custom logic specific to FridaInProcessExecutor
            let target_bytes = input.target_bytes();
            let bytes = target_bytes.as_deref().unwrap_or(&[]);
            return self.helper.borrow_mut().post_exec(bytes);
        }
        Ok(())
    }
}

impl<RT> Named for FridaHelperObserver<'_, RT> {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("FridaHelperObserver");
        &NAME
    }
}

impl<'de, RT> Deserialize<'de> for FridaHelperObserver<'_, RT> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FridaHelperObserverVisitor<'a, RT> {
            phantom: core::marker::PhantomData<&'a RT>,
        }

        impl<'de, 'a, RT> Visitor<'de> for FridaHelperObserverVisitor<'a, RT> {
            type Value = FridaHelperObserver<'a, RT>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a FridaHelperObserver struct")
            }

            fn visit_map<M>(self, _map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                // Construct the struct without deserializing `helper`
                Err(de::Error::custom(
                    "Cannot deserialize `FridaHelperObserver` with a mutable reference",
                ))
            }
        }

        deserializer.deserialize_struct(
            "FridaHelperObserver",
            &[], // No fields to deserialize
            FridaHelperObserverVisitor {
                phantom: core::marker::PhantomData,
            },
        )
    }
}
