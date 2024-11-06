/// An observer that shuts down the Frida helper upon crash
/// This is necessary as we don't want to keep the instrumentation around when processing the crash
use libafl_frida::helper::{FridaInstrumentationHelper, FridaRuntimeTuple};
use libafl::executors::ExitKind;
use libafl::observers::Observer;
use libafl::inputs::{UsesInput, HasTargetBytes};
use serde::Serialize;
use serde::de::{self, Deserialize, Deserializer, Visitor, MapAccess};
use libafl_bolts::{Error, Named};
use alloc::borrow::Cow;
use std::fmt;
use std::cell::RefCell;
use std::rc::Rc;

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Serialize, Debug)]
pub struct FridaHelperObserver<'a, RT> {
    #[serde(skip)]
    // helper: &'a RefCell<FridaInstrumentationHelper<'a, RT>>,
    helper: Rc<RefCell<FridaInstrumentationHelper<'a, RT>>>,
}

impl<'a, RT> FridaHelperObserver<'a, RT>
where
    RT: FridaRuntimeTuple
    {
    /// Creates a new [`FridaHelperObserver`] with the given name.
    #[must_use]
    pub fn new(
        // helper: &'a RefCell<FridaInstrumentationHelper<'a, RT>>,
        helper: Rc<RefCell<FridaInstrumentationHelper<'a, RT>>>
        ) -> Self
    {
        Self {
            helper,
        }
    }
}

impl<'a, S, RT> Observer<S> for FridaHelperObserver<'a, RT>
where
    S: UsesInput,
    S::Input: HasTargetBytes,
    RT: FridaRuntimeTuple
{
    fn post_exec(
        &mut self,
        _state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        if *exit_kind == ExitKind::Crash {
            // Custom implementation logic for `FridaInProcessExecutor`
            log::error!("Custom post_exec called for FridaInProcessExecutorHelper");
            // Add any custom logic specific to FridaInProcessExecutor
            return self.helper.borrow_mut().post_exec(input);
        }
        Ok(())
    }

    fn post_exec_child(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<'a,  RT> Named for FridaHelperObserver<'a,  RT> {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("FridaHelperObserver");
        &NAME
    }
}

impl<'de, 'a, RT> Deserialize<'de> for FridaHelperObserver<'a,  RT> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FridaHelperObserverVisitor<'a,  RT> {
            // marker: std::marker::PhantomData<&'b mut FridaInstrumentationHelper<'a, RT>>,
            marker: std::marker::PhantomData<&'a RT>,
        }

        impl<'de, 'a, RT> Visitor<'de> for FridaHelperObserverVisitor<'a,  RT> {
            type Value = FridaHelperObserver<'a,  RT>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a FridaHelperObserver struct")
            }

            fn visit_map<M>(self, _map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                // Construct the struct without deserializing `helper`
                Err(de::Error::custom("Cannot deserialize `FridaHelperObserver` with a mutable reference"))
            }
        }

        deserializer.deserialize_struct(
            "FridaHelperObserver",
            &[], // No fields to deserialize
            FridaHelperObserverVisitor {
                marker: std::marker::PhantomData,
            },
        )
    }
}