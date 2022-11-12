//! Mutators mutate input during fuzzing.

pub mod scheduled;
pub use scheduled::*;
pub mod mutations;
pub use mutations::*;
pub mod token_mutations;
pub use token_mutations::*;
pub mod encoded_mutations;
pub use encoded_mutations::*;
pub mod mopt_mutator;
pub use mopt_mutator::*;
pub mod gramatron;
pub use gramatron::*;
pub mod grimoire;
pub use grimoire::*;
pub mod tuneable;
pub use tuneable::*;

#[cfg(feature = "nautilus")]
pub mod nautilus;
#[cfg(feature = "nautilus")]
pub use nautilus::*;

use crate::{
    bolts::tuples::{HasConstLen, Named},
    inputs::UsesInput,
    Error,
};

// TODO mutator stats method that produces something that can be sent with the NewTestcase event
// We can use it to report which mutations generated the testcase in the broker logs

/// The result of a mutation.
/// If the mutation got skipped, the target
/// will not be executed with the returned input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutationResult {
    /// The [`Mutator`] mutated this `Input`.
    Mutated,
    /// The [`Mutator`] did not mutate this `Input`. It was `Skipped`.
    Skipped,
}

/// A mutator takes input, and mutates it.
/// Simple as that.
pub trait Mutator<S>
where
    S: UsesInput,
{
    /// Mutate a given input
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut S::Input,
        stage_idx: i32,
    ) -> Result<MutationResult, Error>;

    /// Post-process given the outcome of the execution
    fn post_exec(
        &mut self,
        _state: &mut S,
        _stage_idx: i32,
        _corpus_idx: Option<usize>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

/// A `Tuple` of `Mutators` that can execute multiple `Mutators` in a row.
pub trait MutatorsTuple<S>: HasConstLen
where
    S: UsesInput,
{
    /// Runs the `mutate` function on all `Mutators` in this `Tuple`.
    fn mutate_all(
        &mut self,
        state: &mut S,
        input: &mut S::Input,
        stage_idx: i32,
    ) -> Result<MutationResult, Error>;

    /// Runs the `post_exec` function on all `Mutators` in this `Tuple`.
    fn post_exec_all(
        &mut self,
        state: &mut S,
        stage_idx: i32,
        corpus_idx: Option<usize>,
    ) -> Result<(), Error>;

    /// Gets the [`Mutator`] at the given index and runs the `mutate` function on it.
    fn get_and_mutate(
        &mut self,
        index: usize,
        state: &mut S,
        input: &mut S::Input,
        stage_idx: i32,
    ) -> Result<MutationResult, Error>;

    /// Gets the [`Mutator`] at the given index and runs the `post_exec` function on it.
    fn get_and_post_exec(
        &mut self,
        index: usize,
        state: &mut S,
        stage_idx: i32,
        corpus_idx: Option<usize>,
    ) -> Result<(), Error>;
}

impl<S> MutatorsTuple<S> for ()
where
    S: UsesInput,
{
    fn mutate_all(
        &mut self,
        _state: &mut S,
        _input: &mut S::Input,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        Ok(MutationResult::Skipped)
    }

    fn post_exec_all(
        &mut self,
        _state: &mut S,
        _stage_idx: i32,
        _corpus_idx: Option<usize>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn get_and_mutate(
        &mut self,
        _index: usize,
        _state: &mut S,
        _input: &mut S::Input,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        Ok(MutationResult::Skipped)
    }

    fn get_and_post_exec(
        &mut self,
        _index: usize,
        _state: &mut S,
        _stage_idx: i32,
        _corpus_idx: Option<usize>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<Head, Tail, S> MutatorsTuple<S> for (Head, Tail)
where
    Head: Mutator<S> + Named,
    Tail: MutatorsTuple<S>,
    S: UsesInput,
{
    fn mutate_all(
        &mut self,
        state: &mut S,
        input: &mut S::Input,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let r = self.0.mutate(state, input, stage_idx)?;
        if self.1.mutate_all(state, input, stage_idx)? == MutationResult::Mutated {
            Ok(MutationResult::Mutated)
        } else {
            Ok(r)
        }
    }

    fn post_exec_all(
        &mut self,
        state: &mut S,
        stage_idx: i32,
        corpus_idx: Option<usize>,
    ) -> Result<(), Error> {
        self.0.post_exec(state, stage_idx, corpus_idx)?;
        self.1.post_exec_all(state, stage_idx, corpus_idx)
    }

    fn get_and_mutate(
        &mut self,
        index: usize,
        state: &mut S,
        input: &mut S::Input,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if index == 0 {
            self.0.mutate(state, input, stage_idx)
        } else {
            self.1.get_and_mutate(index - 1, state, input, stage_idx)
        }
    }

    fn get_and_post_exec(
        &mut self,
        index: usize,
        state: &mut S,
        stage_idx: i32,
        corpus_idx: Option<usize>,
    ) -> Result<(), Error> {
        if index == 0 {
            self.0.post_exec(state, stage_idx, corpus_idx)
        } else {
            self.1
                .get_and_post_exec(index - 1, state, stage_idx, corpus_idx)
        }
    }
}

/// `Mutator` Python bindings
#[cfg(feature = "python")]
#[allow(missing_docs)]
pub mod pybind {
    use pyo3::prelude::*;

    use super::{MutationResult, Mutator};
    use crate::{
        inputs::{BytesInput, HasBytesVec},
        mutators::scheduled::pybind::PythonStdHavocMutator,
        state::pybind::{PythonStdState, PythonStdStateWrapper},
        Error,
    };

    #[derive(Clone, Debug)]
    pub struct PyObjectMutator {
        inner: PyObject,
    }

    impl PyObjectMutator {
        #[must_use]
        pub fn new(obj: PyObject) -> Self {
            PyObjectMutator { inner: obj }
        }
    }

    impl Mutator<PythonStdState> for PyObjectMutator {
        fn mutate(
            &mut self,
            state: &mut PythonStdState,
            input: &mut BytesInput,
            stage_idx: i32,
        ) -> Result<MutationResult, Error> {
            let mutated = Python::with_gil(|py| -> PyResult<bool> {
                self.inner
                    .call_method1(
                        py,
                        "mutate",
                        (PythonStdStateWrapper::wrap(state), input.bytes(), stage_idx),
                    )?
                    .extract(py)
            })?;
            Ok(if mutated {
                MutationResult::Mutated
            } else {
                MutationResult::Skipped
            })
        }

        fn post_exec(
            &mut self,
            state: &mut PythonStdState,
            stage_idx: i32,
            corpus_idx: Option<usize>,
        ) -> Result<(), Error> {
            Python::with_gil(|py| -> PyResult<()> {
                self.inner.call_method1(
                    py,
                    "post_exec",
                    (PythonStdStateWrapper::wrap(state), stage_idx, corpus_idx),
                )?;
                Ok(())
            })?;
            Ok(())
        }
    }

    #[derive(Debug, Clone)]
    pub enum PythonMutatorWrapper {
        StdHavoc(Py<PythonStdHavocMutator>),
        Python(PyObjectMutator),
    }

    /// Mutator Trait binding
    #[pyclass(unsendable, name = "Mutator")]
    #[derive(Debug, Clone)]
    pub struct PythonMutator {
        pub wrapper: PythonMutatorWrapper,
    }

    macro_rules! unwrap_me_mut {
        ($wrapper:expr, $name:ident, $body:block) => {
            crate::unwrap_me_mut_body!($wrapper, $name, $body, PythonMutatorWrapper, {
                StdHavoc
            },
            {
                Python(py_wrapper) => {
                    let $name = py_wrapper;
                    $body
                }
            })
        };
    }

    #[pymethods]
    impl PythonMutator {
        #[staticmethod]
        #[must_use]
        pub fn new_std_havoc(mgr: Py<PythonStdHavocMutator>) -> Self {
            Self {
                wrapper: PythonMutatorWrapper::StdHavoc(mgr),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_py(obj: PyObject) -> Self {
            Self {
                wrapper: PythonMutatorWrapper::Python(PyObjectMutator::new(obj)),
            }
        }

        #[must_use]
        pub fn unwrap_py(&self) -> Option<PyObject> {
            match &self.wrapper {
                PythonMutatorWrapper::Python(pyo) => Some(pyo.inner.clone()),
                PythonMutatorWrapper::StdHavoc(_) => None,
            }
        }
    }

    impl Mutator<PythonStdState> for PythonMutator {
        fn mutate(
            &mut self,
            state: &mut PythonStdState,
            input: &mut BytesInput,
            stage_idx: i32,
        ) -> Result<MutationResult, Error> {
            unwrap_me_mut!(self.wrapper, m, { m.mutate(state, input, stage_idx) })
        }

        fn post_exec(
            &mut self,
            state: &mut PythonStdState,
            stage_idx: i32,
            corpus_idx: Option<usize>,
        ) -> Result<(), Error> {
            unwrap_me_mut!(self.wrapper, m, {
                m.post_exec(state, stage_idx, corpus_idx)
            })
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonMutator>()?;
        Ok(())
    }
}
