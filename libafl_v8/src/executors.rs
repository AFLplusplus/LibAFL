use core::{
    fmt,
    fmt::{Debug, Formatter},
    marker::PhantomData,
};
use std::iter;

use libafl::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::{BytesInput, HasBytesVec, Input},
    observers::ObserversTuple,
    Error,
};
pub use v8;
use v8::{
    ArrayBuffer, ContextScope, Function, HandleScope, Local, Script, TryCatch, Uint8Array, Value,
};

pub struct V8Executor<'s1, 's2, EM, I, OT, S, Z>
where
    I: Input + IntoJSValue,
    OT: ObserversTuple<I, S>,
{
    scope: ContextScope<'s1, HandleScope<'s2>>,
    source: String,
    observers: OT,
    phantom: PhantomData<(EM, I, S, Z)>,
}

impl<'s1, 's2, EM, I, OT, S, Z> V8Executor<'s1, 's2, EM, I, OT, S, Z>
where
    I: Input + IntoJSValue,
    OT: ObserversTuple<I, S>,
{
    /// Create a new V8 executor. You MUST invoke `initialize_v8` before using this method.
    pub fn new(
        mut scope: ContextScope<'s1, HandleScope<'s2>>,
        source: &str,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
    ) -> Result<Self, Error> {
        v8::V8::assert_initialized();
        // run the script to initialise the program
        {
            let code = v8::String::new(&mut scope, source).unwrap();

            let mut scope = TryCatch::new(&mut scope);

            let script = Script::compile(&mut scope, code, None).unwrap();
            script.run(&mut scope);

            if let Some(err) = js_err_to_libafl(&mut scope) {
                return Err(err);
            }
        }

        get_harness_func(&mut scope)?; // check that the fuzz harness exists
        Ok(Self {
            scope,
            source: source.to_string(),
            observers,
            phantom: Default::default(),
        })
    }
}

fn get_harness_func<'s1, 's2>(
    scope: &mut ContextScope<'s1, HandleScope<'s2>>,
) -> Result<Local<'s1, Function>, Error> {
    let global = scope.get_current_context().global(scope);
    let harness_name = Local::from(v8::String::new(scope, "LLVMFuzzerTestOneInput").unwrap());
    let func = global.get(scope, harness_name);
    let func = if let Some(func) = func {
        func
    } else {
        return Err(Error::illegal_state(
            "LLVMFuzzerTestOneInput not defined in JS harness",
        ));
    };

    match Local::<Function>::try_from(func) {
        Ok(func) => {
            // good to go!
            Ok(func)
        }
        _ => Err(Error::illegal_state(
            "LLVMFuzzerTestOneInput is defined in JS harness, but wasn't a function",
        )),
    }
}

impl<'s1, 's2, EM, I, OT, S, Z> Executor<EM, I, S, Z> for V8Executor<'s1, 's2, EM, I, OT, S, Z>
where
    I: Input + IntoJSValue,
    OT: ObserversTuple<I, S>,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        let harness = get_harness_func(&mut self.scope)?;

        let scope = &mut HandleScope::new(&mut self.scope);
        let recv = v8::undefined(scope);
        let try_catch = &mut TryCatch::new(scope);

        let input = input.to_js_value(try_catch)?;
        let res = if harness.call(try_catch, recv.into(), &[input]).is_none() {
            Ok(ExitKind::Crash)
        } else {
            Ok(ExitKind::Ok)
        };

        res
    }
}

impl<'s1, 's2, EM, I, OT, S, Z> HasObservers<I, OT, S> for V8Executor<'s1, 's2, EM, I, OT, S, Z>
where
    I: Input + IntoJSValue,
    OT: ObserversTuple<I, S>,
{
    fn observers(&self) -> &OT {
        &self.observers
    }

    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}

impl<'s1, 's2, EM, I, OT, S, Z> Debug for V8Executor<'s1, 's2, EM, I, OT, S, Z>
where
    I: Input + IntoJSValue,
    OT: ObserversTuple<I, S>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("V8Executor")
            .field("source", &self.source)
            .field("observers", &self.observers)
            .finish_non_exhaustive()
    }
}

fn js_err_to_libafl(scope: &mut TryCatch<HandleScope>) -> Option<Error> {
    if !scope.has_caught() {
        None
    } else {
        let exception = scope.exception().unwrap();
        let exception_string = exception
            .to_string(scope)
            .unwrap()
            .to_rust_string_lossy(scope);
        let message = if let Some(message) = scope.message() {
            message
        } else {
            return Some(Error::illegal_state(format!(
                "Provided script threw an error while executing: {}",
                exception_string
            )));
        };

        let filename = message.get_script_resource_name(scope).map_or_else(
            || "(unknown)".into(),
            |s| s.to_string(scope).unwrap().to_rust_string_lossy(scope),
        );
        let line_number = message.get_line_number(scope).unwrap_or_default();

        let source_line = message
            .get_source_line(scope)
            .map(|s| s.to_string(scope).unwrap().to_rust_string_lossy(scope))
            .unwrap();

        let start_column = message.get_start_column();
        let end_column = message.get_end_column();

        let err_underline = iter::repeat(' ')
            .take(start_column)
            .chain(iter::repeat('^').take(end_column - start_column))
            .collect::<String>();

        if let Some(stack_trace) = scope.stack_trace() {
            let stack_trace = unsafe { Local::<v8::String>::cast(stack_trace) };
            let stack_trace = stack_trace
                .to_string(scope)
                .map(|s| s.to_rust_string_lossy(scope));

            if let Some(stack_trace) = stack_trace {
                return Some(Error::illegal_state(format!(
                    "Encountered uncaught JS exception while executing: {}:{}: {}\n{}\n{}\n{}",
                    filename,
                    line_number,
                    exception_string,
                    source_line,
                    err_underline,
                    stack_trace
                )));
            }
        }
        Some(Error::illegal_state(format!(
            "Encountered uncaught JS exception while executing: {}:{}: {}\n{}\n{}",
            filename, line_number, exception_string, source_line, err_underline
        )))
    }
}

pub trait IntoJSValue {
    fn to_js_value<'s>(&self, scope: &mut HandleScope<'s>) -> Result<Local<'s, Value>, Error>;
}

impl IntoJSValue for BytesInput {
    fn to_js_value<'s>(&self, scope: &mut HandleScope<'s>) -> Result<Local<'s, Value>, Error> {
        println!("{}: {:?}", self.bytes().len(), self);
        let store = ArrayBuffer::new_backing_store_from_vec(Vec::from(self.bytes())).make_shared();
        let buffer = ArrayBuffer::with_backing_store(scope, &store);
        let array = Uint8Array::new(scope, buffer, 0, self.bytes().len()).unwrap();
        Ok(array.into())
    }
}
