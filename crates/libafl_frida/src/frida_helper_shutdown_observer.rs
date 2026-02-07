#![allow(missing_docs)]
use alloc::{borrow::Cow, rc::Rc};
use core::{cell::RefCell, fmt};

use libafl::{Error, executors::ExitKind, inputs::Input, observers::Observer};
use libafl_bolts::Named;
use serde::{
    Serialize,
    de::{self, Deserialize, Deserializer, MapAccess, Visitor},
};

use crate::helper::{FridaInstrumentationHelper, FridaRuntimeTuple};

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Serialize, Debug)]
pub struct FridaHelperObserver<'a, RT> {
    #[serde(skip)]
    helper: Rc<RefCell<FridaInstrumentationHelper<'a, RT>>>,
}

impl<'a, RT> FridaHelperObserver<'a, RT>
where
    RT: FridaRuntimeTuple + 'a,
{
    #[must_use]
    pub fn new(
        helper: Rc<RefCell<FridaInstrumentationHelper<'a, RT>>>,
    ) -> Self {
        Self { helper }
    }
}

impl<'a, I, S, RT> Observer<I, S> for FridaHelperObserver<'a, RT>
where
    RT: FridaRuntimeTuple + 'a,
    I: Input,
{
    fn post_exec(&mut self, _state: &mut S, _input: &I, exit_kind: &ExitKind) -> Result<(), Error> {
        if *exit_kind == ExitKind::Crash {
            return self.helper.borrow_mut().post_exec(None);
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
                Err(de::Error::custom(
                    "Cannot deserialize `FridaHelperObserver` with a mutable reference",
                ))
            }
        }

        deserializer.deserialize_struct(
            "FridaHelperObserver",
            &[],
            FridaHelperObserverVisitor {
                phantom: core::marker::PhantomData,
            },
        )
    }
}
