//! Value types for inputs passed to JavaScript targets

use libafl::{
    bolts::AsSlice,
    inputs::{HasTargetBytes, Input},
    Error,
};

use crate::v8::{ArrayBuffer, HandleScope, Local, Value};

/// Trait which converts an input into a JavaScript value. This value can be any JavaScript type.
pub trait IntoJSValue {
    /// Convert this input into a JavaScript value in the provided scope.
    fn to_js_value<'s>(&self, scope: &mut HandleScope<'s>) -> Result<Local<'s, Value>, Error>;
}

impl<B: HasTargetBytes + Input> IntoJSValue for B {
    fn to_js_value<'s>(&self, scope: &mut HandleScope<'s>) -> Result<Local<'s, Value>, Error> {
        let store =
            ArrayBuffer::new_backing_store_from_vec(Vec::from(self.target_bytes().as_slice()))
                .make_shared();
        let buffer = ArrayBuffer::with_backing_store(scope, &store);
        Ok(buffer.into())
    }
}
