//! Value types for inputs passed to JavaScript targets

use libafl::{
    inputs::{BytesInput, HasBytesVec},
    Error,
};

use crate::v8::{ArrayBuffer, HandleScope, Local, Value};

/// Trait which converts an input into a JavaScript value. This value can be any JavaScript type.
pub trait IntoJSValue {
    /// Convert this input into a JavaScript value in the provided scope.
    fn to_js_value<'s>(&self, scope: &mut HandleScope<'s>) -> Result<Local<'s, Value>, Error>;
}

impl IntoJSValue for BytesInput {
    fn to_js_value<'s>(&self, scope: &mut HandleScope<'s>) -> Result<Local<'s, Value>, Error> {
        let store = ArrayBuffer::new_backing_store_from_vec(Vec::from(self.bytes())).make_shared();
        let buffer = ArrayBuffer::with_backing_store(scope, &store);
        Ok(buffer.into())
    }
}
