use alloc::{borrow::Cow, rc::Rc};
use core::{cell::RefCell, fmt};

use libafl::{
    executors::ExitKind,
    inputs::{BytesInputConverter, Input, ToTargetBytesConverter},
    observers::Observer,
};
use libafl_bolts::{Error, Named, AsSlice};
use serde::{
    Serialize,
    de::{self, Deserialize, Deserializer, MapAccess, Visitor},
};

use crate::helper::{FridaInstrumentationHelper, FridaRuntimeTuple};

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Serialize, Debug)]
/// An observer that shuts down the Frida helper upon crash
/// This is necessary as we don't want to keep the instrumentation around when processing the crash
pub struct FridaHelperObserver<'a, RT, Z = BytesInputConverter> {
    #[serde(skip)]
    helper: Rc<RefCell<FridaInstrumentationHelper<'a, RT>>>,
    #[serde(skip)]
    converter: Z,
}

impl<'a, RT> FridaHelperObserver<'a, RT, BytesInputConverter>
where
    RT: FridaRuntimeTuple + 'a,
{
    /// Creates a new FridaHelperObserver with a default byte converter
    #[must_use]
    pub fn new(helper: Rc<RefCell<FridaInstrumentationHelper<'a, RT>>>) -> Self {
        Self {
            helper,
            converter: BytesInputConverter::new(),
        }
    }
}

impl<'a, RT, Z> FridaHelperObserver<'a, RT, Z>
where
    RT: FridaRuntimeTuple + 'a,
{
    /// Creates a new FridaHelperObserver with a custom converter
    #[must_use]
    pub fn with_converter(
        helper: Rc<RefCell<FridaInstrumentationHelper<'a, RT>>>,
        converter: Z,
    ) -> Self {
        Self { helper, converter }
    }
}

impl<'a, I, S, RT, Z> Observer<I, S> for FridaHelperObserver<'a, RT, Z>
where
    // S: UsesInput,
    // S::Input: HasTargetBytes,
    
    I: Input,
    RT: FridaRuntimeTuple + 'a,
    Z: ToTargetBytesConverter<I, S>,
{
    fn post_exec(&mut self, state: &mut S, input: &I, exit_kind: &ExitKind) -> Result<(), Error> {
        if *exit_kind == ExitKind::Crash {
            // Custom implementation logic for `FridaInProcessExecutor`
            log::error!("Custom post_exec called for FridaInProcessExecutorHelper");
            // Add any custom logic specific to FridaInProcessExecutor
            let target_bytes = self.converter.convert_to_target_bytes(state, input);
            return self.helper.borrow_mut().post_exec(target_bytes.as_slice());
        }
        Ok(())
    }
}

impl<RT, Z> Named for FridaHelperObserver<'_, RT, Z> {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("FridaHelperObserver");
        &NAME
    }
}

impl<'de, RT, Z> Deserialize<'de> for FridaHelperObserver<'_, RT, Z> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FridaHelperObserverVisitor<'a, RT, Z> {
            phantom: core::marker::PhantomData<(&'a RT, Z)>,
        }

        impl<'de, 'a, RT, Z> Visitor<'de> for FridaHelperObserverVisitor<'a, RT, Z> {
            type Value = FridaHelperObserver<'a, RT, Z>;

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
