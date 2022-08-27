use core::{
    fmt,
    fmt::{Debug, Formatter},
    marker::PhantomData,
};
use std::{
    borrow::{Borrow, BorrowMut},
    cell::RefCell,
    iter,
    rc::Rc,
    sync::Arc,
};

use deno_core::{v8, JsRuntime, ModuleId, ModuleSpecifier};
use deno_runtime::worker::MainWorker;
use libafl::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::{BytesInput, HasBytesVec, Input},
    observers::ObserversTuple,
    state::State,
    Error,
};
use tokio::{runtime, runtime::Runtime};
use v8::{
    ArrayBuffer, Context, ContextScope, Function, HandleScope, Local, Script, TryCatch, Uint8Array,
    Value,
};

use crate::{v8::Global, Mutex};

pub struct V8Executor<'rt, EM, I, OT, S, Z>
where
    I: Input + IntoJSValue,
    OT: ObserversTuple<I, S>,
    S: State,
{
    id: ModuleId,
    observers: OT,
    rt: &'rt Runtime,
    worker: Arc<Mutex<MainWorker>>,
    phantom: PhantomData<(EM, I, S, Z)>,
}

impl<'rt, EM, I, OT, S, Z> V8Executor<'rt, EM, I, OT, S, Z>
where
    I: Input + IntoJSValue,
    OT: ObserversTuple<I, S>,
    S: State,
{
    /// Create a new V8 executor.
    pub fn new(
        rt: &'rt Runtime,
        worker: Arc<Mutex<MainWorker>>,
        main_module: ModuleSpecifier,
        observers: OT,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
    ) -> Result<Self, Error> {
        let copy = worker.clone();
        let id = match rt.block_on(async {
            let mut locked = copy.lock().await;
            let mod_id = locked.preload_main_module(&main_module).await?;
            let handle = locked.js_runtime.mod_evaluate(mod_id);
            locked.run_event_loop(false).await?;
            handle.await??;

            Ok::<ModuleId, deno_core::anyhow::Error>(mod_id)
        }) {
            Err(e) => return Err(Error::unknown(e.to_string())),
            Ok(id) => id,
        };

        Ok(Self {
            id,
            observers,
            rt,
            worker,
            phantom: Default::default(),
        })
    }

    fn invoke_harness_func(&self, input: &I) -> Result<ExitKind, Error> {
        let id = self.id;
        let copy = self.worker.clone();
        self.rt.block_on(async {
            let mut locked = copy.lock().await;

            let res = {
                let module_namespace = locked.js_runtime.get_module_namespace(id).unwrap();
                let mut scope = locked.js_runtime.handle_scope();
                let module_namespace = Local::<v8::Object>::new(&mut scope, module_namespace);

                let default_export_name = v8::String::new(&mut scope, "default").unwrap();
                let harness = module_namespace
                    .get(&mut scope, default_export_name.into())
                    .unwrap();

                match Local::<Function>::try_from(harness) {
                    Ok(func) => {
                        let recv = v8::undefined(&mut scope);
                        let try_catch = &mut TryCatch::new(&mut scope);
                        let input = input.to_js_value(try_catch)?;
                        let res = func.call(try_catch, recv.into(), &[input]);
                        if res.is_none() {
                            Ok(ExitKind::Crash)
                        } else {
                            Ok(ExitKind::Ok)
                        }
                    }
                    Err(e) => Err(Error::illegal_state(format!(
                        "The default export of the fuzz harness module is not a function: {}",
                        e.to_string(),
                    ))),
                }
            };

            if let Err(e) = locked.run_event_loop(false).await {
                return Err(Error::illegal_state(e.to_string()));
            }
            res
        })
    }
}

impl<'rt, EM, I, OT, S, Z> Executor<EM, I, S, Z> for V8Executor<'rt, EM, I, OT, S, Z>
where
    I: Input + IntoJSValue,
    OT: ObserversTuple<I, S>,
    S: State,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        self.invoke_harness_func(input)
    }
}

impl<'rt, EM, I, OT, S, Z> HasObservers<I, OT, S> for V8Executor<'rt, EM, I, OT, S, Z>
where
    I: Input + IntoJSValue,
    OT: ObserversTuple<I, S>,
    S: State,
{
    fn observers(&self) -> &OT {
        &self.observers
    }

    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}

impl<'rt, EM, I, OT, S, Z> Debug for V8Executor<'rt, EM, I, OT, S, Z>
where
    I: Input + IntoJSValue,
    OT: ObserversTuple<I, S>,
    S: State,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("V8Executor")
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
        let store = ArrayBuffer::new_backing_store_from_vec(Vec::from(self.bytes())).make_shared();
        let buffer = ArrayBuffer::with_backing_store(scope, &store);
        let array = Uint8Array::new(scope, buffer, 0, self.bytes().len()).unwrap();
        Ok(array.into())
    }
}
