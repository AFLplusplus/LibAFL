use pyo3::{prelude::*, types::PyDict};

const LIBAFL_CODE: &str = r#"
class BaseObserver:
    def flush(self):
        pass
    def pre_exec(self, state, input):
        pass
    def post_exec(self, state, input, exit_kind):
        pass
    def pre_exec_child(self, state, input):
        pass
    def post_exec_child(self, state, input, exit_kind):
        pass
    def name(self):
        return type(self).__name__
    def as_observer(self):
        return Observer.new_py(self)

class BaseFeedback:
    def init_state(self, state):
        pass
    def is_interesting(self, state, mgr, input, observers, exit_kind) -> bool:
        return False
    def append_metadata(self, state, observers, testcase):
        pass
    def discard_metadata(self, state, input):
        pass
    def name(self):
        return type(self).__name__
    def as_feedback(self):
        return Feedback.new_py(self)

class BaseExecutor:
    def observers(self) -> ObserversTuple:
        raise NotImplementedError('Implement this yourself')
    def run_target(self, fuzzer, state, mgr, input) -> ExitKind:
        raise NotImplementedError('Implement this yourself')
    def as_executor(self):
        return Executor.new_py(self)

class BaseStage:
    def perform(self, fuzzer, executor, state, manager, corpus_idx):
        pass
    def as_stage(self):
        return Stage.new_py(self)

class BaseMutator:
    def mutate(self, state, input):
        pass
    def post_exec(self, state, corpus_idx):
        pass
    def as_mutator(self):
        return Mutator.new_py(self)

class FnStage(BaseStage):
    def __init__(self, fn):
        self.fn = fn
    def __call__(self, fuzzer, executor, state, manager, corpus_idx):
        self.fn(fuzzer, executor, state, manager, corpus_idx)
    def perform(self, fuzzer, executor, state, manager, corpus_idx):
        self.fn(fuzzer, executor, state, manager, corpus_idx)

def feedback_not(a):
    return NotFeedback(a).as_feedback()

def feedback_and(a, b):
    return EagerAndFeedback(a, b).as_feedback()

def feedback_and_fast(a, b):
    return FastAndFeedback(a, b).as_feedback()

def feedback_or(a, b):
    return EagerOrFeedback(a, b).as_feedback()

def feedback_or_fast(a, b):
    return FastOrFeedback(a, b).as_feedback()
"#;

#[pymodule]
#[pyo3(name = "pylibafl")]
pub fn python_module(py: Python, m: &PyModule) -> PyResult<()> {
    pyo3_log::init();

    let modules = py.import("sys")?.getattr("modules")?;

    let sugar_module = PyModule::new(py, "sugar")?;
    libafl_sugar::python_module(py, sugar_module)?;
    m.add_submodule(sugar_module)?;
    modules.set_item("pylibafl.sugar", sugar_module)?;

    #[cfg(target_os = "linux")]
    {
        let qemu_module = PyModule::new(py, "qemu")?;
        libafl_qemu::python_module(py, qemu_module)?;
        m.add_submodule(qemu_module)?;
        modules.set_item("pylibafl.qemu", qemu_module)?;
    }

    let bolts_module = PyModule::new(py, "libafl_bolts")?;
    libafl_bolts::pybind::python_module(py, bolts_module)?;
    m.add_submodule(bolts_module)?;
    modules.set_item("pylibafl.libafl_bolts", bolts_module)?;

    let libafl_module = PyModule::new(py, "libafl")?;
    libafl::pybind::python_module(py, libafl_module)?;

    libafl_module.add("__builtins__", py.import("builtins")?)?;

    let locals = PyDict::new(py);
    py.run(LIBAFL_CODE, Some(libafl_module.dict()), Some(locals))?;
    for (key, val) in locals.iter() {
        libafl_module.add(key.extract::<&str>()?, val)?;
    }

    m.add_submodule(libafl_module)?;
    modules.set_item("pylibafl.libafl", libafl_module)?;

    Ok(())
}
