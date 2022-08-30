//! Executors for JavaScript targets
//!
//! Currently, the only provided executor is `V8Executor`, but additional executors for other
//! environments may be added later for different JavaScript contexts.

use core::{
    fmt,
    fmt::{Debug, Formatter},
    marker::PhantomData,
};

use deno_core::{v8, ModuleId, ModuleSpecifier};
use libafl::{
    events::{EventFirer, EventRestarter},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::Feedback,
    inputs::Input,
    observers::ObserversTuple,
    state::{HasClientPerfMonitor, HasSolutions, State},
    Error, HasObjective,
};
use v8::{Function, Local, TryCatch};

use crate::{values::IntoJSValue, RUNTIME, WORKER};

/// Executor which executes JavaScript using Deno and V8.
pub struct V8Executor<I, OT, S>
where
    I: Input + IntoJSValue,
    OT: ObserversTuple<I, S>,
    S: State,
{
    id: ModuleId,
    observers: OT,
    phantom: PhantomData<(I, S)>,
}

impl<I, OT, S> V8Executor<I, OT, S>
where
    I: Input + IntoJSValue,
    OT: ObserversTuple<I, S>,
    S: State,
{
    /// Create a new V8 executor.
    pub fn new<EM, OF, Z>(
        main_module: ModuleSpecifier,
        observers: OT,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<I> + EventRestarter<S>,
        OF: Feedback<I, S>,
        S: HasSolutions<I> + HasClientPerfMonitor,
        Z: HasObjective<I, OF, S>,
    {
        let id = match unsafe { RUNTIME.as_ref() }
            .expect("Runtime must be initialized before creating executors; use initialize_v8!")
            .block_on(async {
                let worker = unsafe { WORKER.as_mut() }.expect(
                    "Worker must be initialized before creating executors; use initialize_v8!",
                );
                let mod_id = worker.preload_main_module(&main_module).await?;
                let handle = worker.js_runtime.mod_evaluate(mod_id);
                worker.run_event_loop(false).await?;
                handle.await??;

                Ok::<ModuleId, deno_core::anyhow::Error>(mod_id)
            }) {
            Err(e) => return Err(Error::unknown(e.to_string())),
            Ok(id) => id,
        };

        Ok(Self {
            id,
            observers,
            phantom: Default::default(),
        })
    }

    fn invoke_harness_func(&self, input: &I) -> Result<ExitKind, Error> {
        let id = self.id;
        unsafe { RUNTIME.as_ref() }.unwrap().block_on(async {
            let worker = unsafe { WORKER.as_mut() }.unwrap();

            let res = {
                let module_namespace = worker.js_runtime.get_module_namespace(id).unwrap();
                let mut scope = worker.js_runtime.handle_scope();
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
                            println!(
                                "{}",
                                crate::js_err_to_libafl(try_catch).unwrap().to_string()
                            );
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

            if let Err(e) = worker.run_event_loop(false).await {
                return Err(Error::illegal_state(e.to_string()));
            }
            res
        })
    }

    /// Fetches the ID of the main module for hooking
    pub fn main_module_id(&self) -> ModuleId {
        self.id
    }
}

impl<EM, I, OT, S, Z> Executor<EM, I, S, Z> for V8Executor<I, OT, S>
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

impl<I, OT, S> HasObservers<I, OT, S> for V8Executor<I, OT, S>
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

impl<I, OT, S> Debug for V8Executor<I, OT, S>
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
