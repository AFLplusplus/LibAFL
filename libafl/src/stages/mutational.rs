//| The [`MutationalStage`] is the default stage used during fuzzing.
//! For the current input, it will perform a range of random mutations, and then run them in the executor.

use core::marker::PhantomData;

use crate::{
    bolts::rands::Rand,
    corpus::Corpus,
    fuzzer::Evaluator,
    inputs::Input,
    mark_feature_time,
    mutators::Mutator,
    stages::Stage,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasRand},
    Error,
};

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;

// TODO multi mutators stage

/// A Mutational stage is the stage in a fuzzing run that mutates inputs.
/// Mutational stages will usually have a range of mutations that are
/// being applied to the input one by one, between executions.
pub trait MutationalStage<E, EM, I, M, S, Z>: Stage<E, EM, S, Z>
where
    M: Mutator<I, S>,
    I: Input,
    S: HasClientPerfMonitor + HasCorpus<I>,
    Z: Evaluator<E, EM, I, S>,
{
    /// The mutator registered for this stage
    fn mutator(&self) -> &M;

    /// The mutator registered for this stage (mutable)
    fn mutator_mut(&mut self) -> &mut M;

    /// Gets the number of iterations this mutator should run for.
    fn iterations(&self, state: &mut S, corpus_idx: usize) -> Result<usize, Error>;

    /// Runs this (mutational) stage for the given testcase
    #[allow(clippy::cast_possible_wrap)] // more than i32 stages on 32 bit system - highly unlikely...
    fn perform_mutational(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let num = self.iterations(state, corpus_idx)?;

        for i in 0..num {
            start_timer!(state);
            let mut input = state
                .corpus()
                .get(corpus_idx)?
                .borrow_mut()
                .load_input()?
                .clone();
            mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

            start_timer!(state);
            self.mutator_mut().mutate(state, &mut input, i as i32)?;
            mark_feature_time!(state, PerfFeature::Mutate);

            // Time is measured directly the `evaluate_input` function
            let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, input)?;

            start_timer!(state);
            self.mutator_mut().post_exec(state, i as i32, corpus_idx)?;
            mark_feature_time!(state, PerfFeature::MutatePostExec);
        }
        Ok(())
    }
}

/// Default value, how many iterations each stage gets, as an upper bound.
/// It may randomly continue earlier.
pub static DEFAULT_MUTATIONAL_MAX_ITERATIONS: u64 = 128;

/// The default mutational stage
#[derive(Clone, Debug)]
pub struct StdMutationalStage<E, EM, I, M, S, Z>
where
    M: Mutator<I, S>,
    I: Input,
    S: HasClientPerfMonitor + HasCorpus<I> + HasRand,
    Z: Evaluator<E, EM, I, S>,
{
    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, S, Z)>,
}

impl<E, EM, I, M, S, Z> MutationalStage<E, EM, I, M, S, Z> for StdMutationalStage<E, EM, I, M, S, Z>
where
    M: Mutator<I, S>,
    I: Input,
    S: HasClientPerfMonitor + HasCorpus<I> + HasRand,
    Z: Evaluator<E, EM, I, S>,
{
    /// The mutator, added to this stage
    #[inline]
    fn mutator(&self) -> &M {
        &self.mutator
    }

    /// The list of mutators, added to this stage (as mutable ref)
    #[inline]
    fn mutator_mut(&mut self) -> &mut M {
        &mut self.mutator
    }

    /// Gets the number of iterations as a random number
    fn iterations(&self, state: &mut S, _corpus_idx: usize) -> Result<usize, Error> {
        Ok(1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS) as usize)
    }
}

impl<E, EM, I, M, S, Z> Stage<E, EM, S, Z> for StdMutationalStage<E, EM, I, M, S, Z>
where
    M: Mutator<I, S>,
    I: Input,
    S: HasClientPerfMonitor + HasCorpus<I> + HasRand,
    Z: Evaluator<E, EM, I, S>,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let ret = self.perform_mutational(fuzzer, executor, state, manager, corpus_idx);

        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();

        ret
    }
}

impl<E, EM, I, M, S, Z> StdMutationalStage<E, EM, I, M, S, Z>
where
    M: Mutator<I, S>,
    I: Input,
    S: HasClientPerfMonitor + HasCorpus<I> + HasRand,
    Z: Evaluator<E, EM, I, S>,
{
    /// Creates a new default mutational stage
    pub fn new(mutator: M) -> Self {
        Self {
            mutator,
            phantom: PhantomData,
        }
    }
}

#[cfg(feature = "python")]
/// `StdMutationalStage` Python bindings
pub mod pybind {
    use crate::bolts::tuples::tuple_list_type;
    use crate::inputs::BytesInput;
    pub use crate::mutators::mutations::*;
    pub use crate::mutators::mutations::*;
    use crate::mutators::{havoc_mutations, StdScheduledMutator};
    use crate::stages::StdMutationalStage;
    use pyo3::prelude::*;

    type HavocMutationsType = tuple_list_type!(
        BitFlipMutator,
        ByteFlipMutator,
        ByteIncMutator,
        ByteDecMutator,
        ByteNegMutator,
        ByteRandMutator,
        ByteAddMutator,
        WordAddMutator,
        DwordAddMutator,
        QwordAddMutator,
        ByteInterestingMutator,
        WordInterestingMutator,
        DwordInterestingMutator,
        BytesDeleteMutator,
        BytesDeleteMutator,
        BytesDeleteMutator,
        BytesDeleteMutator,
        BytesExpandMutator,
        BytesInsertMutator,
        BytesRandInsertMutator,
        BytesSetMutator,
        BytesRandSetMutator,
        BytesCopyMutator,
        BytesInsertCopyMutator,
        BytesSwapMutator,
        CrossoverInsertMutator,
        CrossoverReplaceMutator,
    );

    macro_rules! define_python_std_mutational_stage {
        ($struct_name:ident, $py_name:tt, $my_std_state_type_name: ident, $my_std_fuzzer_type_name: ident, $executor_name: ident, $event_manager_name: ident) => {
            use crate::events::pybind::$event_manager_name;
            use crate::executors::pybind::$executor_name;
            use crate::fuzzer::pybind::$my_std_fuzzer_type_name;
            use crate::state::pybind::$my_std_state_type_name;

            #[pyclass(unsendable, name = $py_name)]
            #[derive(Debug)]
            /// Python class for StdMutationalStage
            pub struct $struct_name {
                /// Rust wrapped StdMutationalStage object
                pub std_mutational_stage: StdMutationalStage<
                    $executor_name,
                    $event_manager_name,
                    BytesInput,
                    StdScheduledMutator<BytesInput, HavocMutationsType, $my_std_state_type_name>,
                    $my_std_state_type_name,
                    $my_std_fuzzer_type_name,
                >,
            }

            #[pymethods]
            impl $struct_name {
                #[staticmethod]
                fn new_from_scheduled_havoc_mutations() -> Self {
                    Self {
                        std_mutational_stage: StdMutationalStage::new(StdScheduledMutator::new(
                            havoc_mutations(),
                        )),
                    }
                }
            }
        };
    }

    define_python_std_mutational_stage!(
        PythonStdScheduledHavocMutationsStageI8,
        "StdScheduledHavocMutationsStageI8",
        MyStdStateI8,
        MyStdFuzzerI8,
        PythonExecutorI8,
        PythonEventManagerI8
    );

    define_python_std_mutational_stage!(
        PythonStdScheduledHavocMutationsStageI16,
        "StdScheduledHavocMutationsStageI16",
        MyStdStateI16,
        MyStdFuzzerI16,
        PythonExecutorI16,
        PythonEventManagerI16
    );
    define_python_std_mutational_stage!(
        PythonStdScheduledHavocMutationsStageI32,
        "StdScheduledHavocMutationsStageI32",
        MyStdStateI32,
        MyStdFuzzerI32,
        PythonExecutorI32,
        PythonEventManagerI32
    );
    define_python_std_mutational_stage!(
        PythonStdScheduledHavocMutationsStageI64,
        "StdScheduledHavocMutationsStageI64",
        MyStdStateI64,
        MyStdFuzzerI64,
        PythonExecutorI64,
        PythonEventManagerI64
    );

    define_python_std_mutational_stage!(
        PythonStdScheduledHavocMutationsStageU8,
        "StdScheduledHavocMutationsStageU8",
        MyStdStateU8,
        MyStdFuzzerU8,
        PythonExecutorU8,
        PythonEventManagerU8
    );

    define_python_std_mutational_stage!(
        PythonStdScheduledHavocMutationsStageU16,
        "StdScheduledHavocMutationsStageU16",
        MyStdStateU16,
        MyStdFuzzerU16,
        PythonExecutorU16,
        PythonEventManagerU16
    );
    define_python_std_mutational_stage!(
        PythonStdScheduledHavocMutationsStageU32,
        "StdScheduledHavocMutationsStageU32",
        MyStdStateU32,
        MyStdFuzzerU32,
        PythonExecutorU32,
        PythonEventManagerU32
    );
    define_python_std_mutational_stage!(
        PythonStdScheduledHavocMutationsStageU64,
        "StdScheduledHavocMutationsStageU64",
        MyStdStateU64,
        MyStdFuzzerU64,
        PythonExecutorU64,
        PythonEventManagerU64
    );

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonStdScheduledHavocMutationsStageI8>()?;
        m.add_class::<PythonStdScheduledHavocMutationsStageI16>()?;
        m.add_class::<PythonStdScheduledHavocMutationsStageI32>()?;
        m.add_class::<PythonStdScheduledHavocMutationsStageI64>()?;

        m.add_class::<PythonStdScheduledHavocMutationsStageU8>()?;
        m.add_class::<PythonStdScheduledHavocMutationsStageU16>()?;
        m.add_class::<PythonStdScheduledHavocMutationsStageU32>()?;
        m.add_class::<PythonStdScheduledHavocMutationsStageU64>()?;
        Ok(())
    }
}
