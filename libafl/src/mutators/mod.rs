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

#[cfg(feature = "nautilus")]
pub mod nautilus;
#[cfg(feature = "nautilus")]
pub use nautilus::*;

use crate::{
    bolts::tuples::{HasConstLen, Named},
    inputs::Input,
    Error,
};

// TODO mutator stats method that produces something that can be sent with the NewTestcase event
// We can use it to report which mutations generated the testcase in the broker logs

/// The result of a mutation.
/// If the mutation got skipped, the target
/// will not be executed with the returned input.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MutationResult {
    /// The [`Mutator`] mutated this `Input`.
    Mutated,
    /// The [`Mutator`] did not mutate this `Input`. It was `Skipped`.
    Skipped,
}

/// A mutator takes input, and mutates it.
/// Simple as that.
pub trait Mutator<I, S>
where
    I: Input,
{
    /// Mutate a given input
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
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
pub trait MutatorsTuple<I, S>: HasConstLen
where
    I: Input,
{
    /// Runs the `mutate` function on all `Mutators` in this `Tuple`.
    fn mutate_all(
        &mut self,
        state: &mut S,
        input: &mut I,
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
        input: &mut I,
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

impl<I, S> MutatorsTuple<I, S> for ()
where
    I: Input,
{
    fn mutate_all(
        &mut self,
        _state: &mut S,
        _input: &mut I,
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
        _input: &mut I,
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

impl<Head, Tail, I, S> MutatorsTuple<I, S> for (Head, Tail)
where
    Head: Mutator<I, S> + Named,
    Tail: MutatorsTuple<I, S>,
    I: Input,
{
    fn mutate_all(
        &mut self,
        state: &mut S,
        input: &mut I,
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
        input: &mut I,
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
pub mod pybind {
    use crate::inputs::BytesInput;
    use crate::mutators::{MutationResult, Mutator};
    use crate::Error;
    use pyo3::prelude::*;

    macro_rules! define_python_mutator {
        ($struct_name_trait:ident, $py_name_trait:tt, $wrapper_name: ident, $std_scheduled_mutator_name: ident, $my_std_state_type_name: ident) => {
            use crate::mutators::scheduled::pybind::$std_scheduled_mutator_name;
            use crate::state::pybind::$my_std_state_type_name;

            #[derive(Debug)]
            enum $wrapper_name {
                StdScheduled(*mut $std_scheduled_mutator_name),
            }

            /// Mutator Trait binding
            #[pyclass(unsendable, name = $py_name_trait)]
            #[derive(Debug)]
            pub struct $struct_name_trait {
                mutator: $wrapper_name,
            }

            #[pymethods]
            impl $struct_name_trait {
                #[staticmethod]
                fn new_from_std_scheduled(
                    py_std_scheduled_mutator: &mut $std_scheduled_mutator_name,
                ) -> Self {
                    Self {
                        mutator: $wrapper_name::StdScheduled(py_std_scheduled_mutator),
                    }
                }
            }

            impl Mutator<BytesInput, $my_std_state_type_name> for $struct_name_trait {
                #[inline]
                fn mutate(
                    &mut self,
                    state: &mut $my_std_state_type_name,
                    input: &mut BytesInput,
                    stage_idx: i32,
                ) -> Result<MutationResult, Error> {
                    unsafe {
                        match self.mutator {
                            $wrapper_name::StdScheduled(py_std_scheduled_mutator) => {
                                (*py_std_scheduled_mutator)
                                    .std_scheduled_mutator
                                    .mutate(state, input, stage_idx)
                            }
                        }
                    }
                }
            }
        };
    }

    define_python_mutator!(
        PythonMutatorI8,
        "MutatorI8",
        PythonMutatorWrapperI8,
        PythonStdScheduledMutatorI8,
        MyStdStateI8
    );

    define_python_mutator!(
        PythonMutatorI16,
        "MutatorI16",
        PythonMutatorWrapperI16,
        PythonStdScheduledMutatorI16,
        MyStdStateI16
    );

    define_python_mutator!(
        PythonMutatorI32,
        "MutatorI32",
        PythonMutatorWrapperI32,
        PythonStdScheduledMutatorI32,
        MyStdStateI32
    );

    define_python_mutator!(
        PythonMutatorI64,
        "MutatorI64",
        PythonMutatorWrapperI64,
        PythonStdScheduledMutatorI64,
        MyStdStateI64
    );

    define_python_mutator!(
        PythonMutatorU8,
        "MutatorU8",
        PythonMutatorWrapperU8,
        PythonStdScheduledMutatorU8,
        MyStdStateU8
    );
    define_python_mutator!(
        PythonMutatorU16,
        "MutatorU16",
        PythonMutatorWrapperU16,
        PythonStdScheduledMutatorU16,
        MyStdStateU16
    );
    define_python_mutator!(
        PythonMutatorU32,
        "MutatorU32",
        PythonMutatorWrapperU32,
        PythonStdScheduledMutatorU32,
        MyStdStateU32
    );
    define_python_mutator!(
        PythonMutatorU64,
        "MutatorU64",
        PythonMutatorWrapperU64,
        PythonStdScheduledMutatorU64,
        MyStdStateU64
    );

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonMutatorI8>()?;
        m.add_class::<PythonMutatorI16>()?;
        m.add_class::<PythonMutatorI32>()?;
        m.add_class::<PythonMutatorI64>()?;

        m.add_class::<PythonMutatorU8>()?;
        m.add_class::<PythonMutatorU16>()?;
        m.add_class::<PythonMutatorU32>()?;
        m.add_class::<PythonMutatorU64>()?;
        Ok(())
    }
}
