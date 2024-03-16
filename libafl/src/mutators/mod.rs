//! Mutators mutate input during fuzzing.

pub mod scheduled;
use core::fmt;

pub use scheduled::*;
pub mod mutations;
pub use mutations::*;
pub mod token_mutations;
use serde::{Deserialize, Serialize};
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

#[cfg(feature = "unicode")]
pub mod string;
#[cfg(feature = "unicode")]
pub use string::*;

#[cfg(feature = "multipart_inputs")]
pub mod multi;
#[cfg(feature = "multipart_inputs")]
pub use multi::*;

#[cfg(feature = "nautilus")]
pub mod nautilus;

use alloc::{boxed::Box, vec::Vec};

use libafl_bolts::{tuples::IntoVec, HasLen, Named};
#[cfg(feature = "nautilus")]
pub use nautilus::*;
use tuple_list::NonEmptyTuple;

use crate::{corpus::CorpusId, Error};

// TODO mutator stats method that produces something that can be sent with the NewTestcase event
// We can use it to report which mutations generated the testcase in the broker logs

/// The index of a mutation in the mutations tuple
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
pub struct MutationId(pub(crate) usize);

impl fmt::Display for MutationId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MutationId({})", self.0)
    }
}

impl From<usize> for MutationId {
    fn from(value: usize) -> Self {
        MutationId(value)
    }
}

impl From<u64> for MutationId {
    fn from(value: u64) -> Self {
        MutationId(value as usize)
    }
}

impl From<i32> for MutationId {
    #[allow(clippy::cast_sign_loss)]
    fn from(value: i32) -> Self {
        debug_assert!(value >= 0);
        MutationId(value as usize)
    }
}

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
pub trait Mutator<I, S>: Named {
    /// Mutate a given input
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error>;

    /// Post-process given the outcome of the execution
    /// `new_corpus_idx` will be `Some` if a new `Testcase` was created this execution.
    #[inline]
    fn post_exec(
        &mut self,
        _state: &mut S,
        _new_corpus_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

/// A mutator that takes input, and returns a vector of mutated inputs.
/// Simple as that.
pub trait MultiMutator<I, S>: Named {
    /// Mutate a given input up to `max_count` times,
    /// or as many times as appropriate, if no `max_count` is given
    fn multi_mutate(
        &mut self,
        state: &mut S,
        input: &I,
        max_count: Option<usize>,
    ) -> Result<Vec<I>, Error>;

    /// Post-process given the outcome of the execution
    /// `new_corpus_idx` will be `Some` if a new `Testcase` was created this execution.
    #[inline]
    fn multi_post_exec(
        &mut self,
        _state: &mut S,
        _new_corpus_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

/// A `Tuple` of `Mutators` that can execute multiple `Mutators` in a row.
pub trait MutatorsTuple<I, S>: HasLen {
    /// Runs the `mutate` function on all `Mutators` in this `Tuple`.
    fn mutate_all(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error>;

    /// Runs the `post_exec` function on all `Mutators` in this `Tuple`.
    /// `new_corpus_idx` will be `Some` if a new `Testcase` was created this execution.
    fn post_exec_all(
        &mut self,
        state: &mut S,
        new_corpus_idx: Option<CorpusId>,
    ) -> Result<(), Error>;

    /// Gets the [`Mutator`] at the given index and runs the `mutate` function on it.
    fn get_and_mutate(
        &mut self,
        index: MutationId,
        state: &mut S,
        input: &mut I,
    ) -> Result<MutationResult, Error>;

    /// Gets the [`Mutator`] at the given index and runs the `post_exec` function on it.
    /// `new_corpus_idx` will be `Some` if a new `Testcase` was created this execution.
    fn get_and_post_exec(
        &mut self,
        index: usize,
        state: &mut S,

        corpus_idx: Option<CorpusId>,
    ) -> Result<(), Error>;

    /// Gets all names of the wrapped [`Mutator`]`s`, reversed.
    fn names_reversed(&self) -> Vec<&str>;

    /// Gets all names of the wrapped [`Mutator`]`s`.
    fn names(&self) -> Vec<&str>;
}

impl<I, S> MutatorsTuple<I, S> for () {
    #[inline]
    fn mutate_all(&mut self, _state: &mut S, _input: &mut I) -> Result<MutationResult, Error> {
        Ok(MutationResult::Skipped)
    }

    #[inline]
    fn post_exec_all(
        &mut self,
        _state: &mut S,
        _new_corpus_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        Ok(())
    }

    #[inline]
    fn get_and_mutate(
        &mut self,
        _index: MutationId,
        _state: &mut S,
        _input: &mut I,
    ) -> Result<MutationResult, Error> {
        Ok(MutationResult::Skipped)
    }

    #[inline]
    fn get_and_post_exec(
        &mut self,
        _index: usize,
        _state: &mut S,
        _new_corpus_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        Ok(())
    }

    #[inline]
    fn names_reversed(&self) -> Vec<&str> {
        Vec::new()
    }

    #[inline]
    fn names(&self) -> Vec<&str> {
        Vec::new()
    }
}

impl<Head, Tail, I, S> MutatorsTuple<I, S> for (Head, Tail)
where
    Head: Mutator<I, S>,
    Tail: MutatorsTuple<I, S>,
{
    fn mutate_all(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        let r = self.0.mutate(state, input)?;
        if self.1.mutate_all(state, input)? == MutationResult::Mutated {
            Ok(MutationResult::Mutated)
        } else {
            Ok(r)
        }
    }

    fn post_exec_all(
        &mut self,
        state: &mut S,
        new_corpus_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        self.0.post_exec(state, new_corpus_idx)?;
        self.1.post_exec_all(state, new_corpus_idx)
    }

    fn get_and_mutate(
        &mut self,
        index: MutationId,
        state: &mut S,
        input: &mut I,
    ) -> Result<MutationResult, Error> {
        if index.0 == 0 {
            self.0.mutate(state, input)
        } else {
            self.1.get_and_mutate((index.0 - 1).into(), state, input)
        }
    }

    fn get_and_post_exec(
        &mut self,
        index: usize,
        state: &mut S,
        new_corpus_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        if index == 0 {
            self.0.post_exec(state, new_corpus_idx)
        } else {
            self.1.get_and_post_exec(index - 1, state, new_corpus_idx)
        }
    }

    fn names_reversed(&self) -> Vec<&str> {
        let mut ret = self.1.names_reversed();
        ret.push(self.0.name());
        ret
    }

    fn names(&self) -> Vec<&str> {
        let mut ret = self.names_reversed();
        ret.reverse();
        ret
    }
}

impl<Head, Tail, I, S> IntoVec<Box<dyn Mutator<I, S>>> for (Head, Tail)
where
    Head: Mutator<I, S> + 'static,
    Tail: IntoVec<Box<dyn Mutator<I, S>>>,
{
    fn into_vec_reversed(self) -> Vec<Box<dyn Mutator<I, S>>> {
        let (head, tail) = self.uncons();
        let mut ret = tail.into_vec_reversed();
        ret.push(Box::new(head));
        ret
    }

    fn into_vec(self) -> Vec<Box<dyn Mutator<I, S>>> {
        let mut ret = self.into_vec_reversed();
        ret.reverse();
        ret
    }
}

impl<Tail, I, S> MutatorsTuple<I, S> for (Tail,)
where
    Tail: MutatorsTuple<I, S>,
{
    fn mutate_all(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        self.0.mutate_all(state, input)
    }

    fn post_exec_all(
        &mut self,
        state: &mut S,
        new_corpus_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        self.0.post_exec_all(state, new_corpus_idx)
    }

    fn get_and_mutate(
        &mut self,
        index: MutationId,
        state: &mut S,
        input: &mut I,
    ) -> Result<MutationResult, Error> {
        self.0.get_and_mutate(index, state, input)
    }

    fn get_and_post_exec(
        &mut self,
        index: usize,
        state: &mut S,
        new_corpus_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        self.0.get_and_post_exec(index, state, new_corpus_idx)
    }

    fn names(&self) -> Vec<&str> {
        self.0.names()
    }

    fn names_reversed(&self) -> Vec<&str> {
        self.0.names_reversed()
    }
}

impl<Tail, I, S> IntoVec<Box<dyn Mutator<I, S>>> for (Tail,)
where
    Tail: IntoVec<Box<dyn Mutator<I, S>>>,
{
    fn into_vec(self) -> Vec<Box<dyn Mutator<I, S>>> {
        self.0.into_vec()
    }
}

impl<I, S> MutatorsTuple<I, S> for Vec<Box<dyn Mutator<I, S>>> {
    fn mutate_all(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        self.iter_mut()
            .try_fold(MutationResult::Skipped, |ret, mutator| {
                if mutator.mutate(state, input)? == MutationResult::Mutated {
                    Ok(MutationResult::Mutated)
                } else {
                    Ok(ret)
                }
            })
    }

    fn post_exec_all(
        &mut self,
        state: &mut S,
        new_corpus_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        for mutator in self.iter_mut() {
            mutator.post_exec(state, new_corpus_idx)?;
        }
        Ok(())
    }

    fn get_and_mutate(
        &mut self,
        index: MutationId,
        state: &mut S,
        input: &mut I,
    ) -> Result<MutationResult, Error> {
        let mutator = self
            .get_mut(index.0)
            .ok_or_else(|| Error::key_not_found("Mutator with id {index:?} not found."))?;
        mutator.mutate(state, input)
    }

    fn get_and_post_exec(
        &mut self,
        index: usize,
        state: &mut S,
        new_corpus_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        let mutator = self
            .get_mut(index)
            .ok_or_else(|| Error::key_not_found("Mutator with id {index:?} not found."))?;
        mutator.post_exec(state, new_corpus_idx)
    }

    fn names_reversed(&self) -> Vec<&str> {
        self.iter().rev().map(|x| x.name()).collect()
    }

    fn names(&self) -> Vec<&str> {
        self.iter().map(|x| x.name()).collect()
    }
}

impl<I, S> IntoVec<Box<dyn Mutator<I, S>>> for Vec<Box<dyn Mutator<I, S>>> {
    fn into_vec(self) -> Vec<Box<dyn Mutator<I, S>>> {
        self
    }
}

/// `Mutator` Python bindings
#[cfg(feature = "python")]
#[allow(missing_docs)]
pub mod pybind {
    use core::ffi::CStr;

    use libafl_bolts::Named;
    use pyo3::{prelude::*, AsPyPointer};

    use super::{MutationResult, Mutator};
    use crate::{
        corpus::CorpusId,
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

    impl Named for PyObjectMutator {
        fn name(&self) -> &str {
            unsafe { CStr::from_ptr((*(*self.inner.as_ptr()).ob_type).tp_name) }
                .to_str()
                .unwrap()
        }
    }

    impl Mutator<BytesInput, PythonStdState> for PyObjectMutator {
        fn mutate(
            &mut self,
            state: &mut PythonStdState,
            input: &mut BytesInput,
        ) -> Result<MutationResult, Error> {
            let mutated = Python::with_gil(|py| -> PyResult<bool> {
                self.inner
                    .call_method1(
                        py,
                        "mutate",
                        (PythonStdStateWrapper::wrap(state), input.bytes()),
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

            corpus_idx: Option<CorpusId>,
        ) -> Result<(), Error> {
            Python::with_gil(|py| -> PyResult<()> {
                self.inner.call_method1(
                    py,
                    "post_exec",
                    (PythonStdStateWrapper::wrap(state), corpus_idx.map(|x| x.0)),
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
            libafl_bolts::unwrap_me_mut_body!($wrapper, $name, $body, PythonMutatorWrapper, {
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

    impl Named for PythonMutator {
        fn name(&self) -> &str {
            match &self.wrapper {
                PythonMutatorWrapper::Python(pyo) => pyo.name(),
                PythonMutatorWrapper::StdHavoc(_) => "StdHavocPythonMutator",
            }
        }
    }

    impl Mutator<BytesInput, PythonStdState> for PythonMutator {
        fn mutate(
            &mut self,
            state: &mut PythonStdState,
            input: &mut BytesInput,
        ) -> Result<MutationResult, Error> {
            unwrap_me_mut!(self.wrapper, m, { m.mutate(state, input) })
        }

        fn post_exec(
            &mut self,
            state: &mut PythonStdState,

            corpus_idx: Option<CorpusId>,
        ) -> Result<(), Error> {
            unwrap_me_mut!(self.wrapper, m, { m.post_exec(state, corpus_idx) })
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonMutator>()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, vec::Vec};

    use libafl_bolts::{rands::StdRand, tuples::IntoVec};

    use crate::{
        corpus::InMemoryCorpus,
        inputs::BytesInput,
        mutators::{havoc_mutations, Mutator, MutatorsTuple},
        state::StdState,
    };

    type TestStdStateType =
        StdState<BytesInput, InMemoryCorpus<BytesInput>, StdRand, InMemoryCorpus<BytesInput>>;

    #[test]
    fn test_tuple_into_vec() {
        let mutators = havoc_mutations::<BytesInput>();
        let names_before = MutatorsTuple::<BytesInput, TestStdStateType>::names(&mutators);

        let mutators = havoc_mutations::<BytesInput>();
        let mutators_vec: Vec<Box<dyn Mutator<BytesInput, TestStdStateType>>> = mutators.into_vec();
        assert_eq!(names_before, mutators_vec.names());
    }
}
