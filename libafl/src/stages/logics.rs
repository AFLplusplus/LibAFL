//! Stage wrappers that add logics to stage list

use core::marker::PhantomData;

use crate::{
    stages::{HasCurrentStage, HasNestedStageStatus, Stage, StageProgress, StagesTuple},
    state::UsesState,
    Error,
};

/// Progress for nested stages. This merely enters/exits the inner stage's scope.
#[derive(Debug)]
pub struct NestedStageProgress;

impl<S, ST> StageProgress<S, ST> for NestedStageProgress
where
    S: HasNestedStageStatus,
{
    fn initialize_progress(state: &mut S, _stage: &ST) -> Result<(), Error> {
        state.enter_inner_stage()?;
        Ok(())
    }

    fn clear_progress(state: &mut S, _stage: &ST) -> Result<(), Error> {
        state.exit_inner_stage()?;
        Ok(())
    }

    fn progress<'a>(_state: &'a S, _stage: &ST) -> Result<&'a Self, Error> {
        unimplemented!("NestedStageProgress should not be queried")
    }

    fn progress_mut<'a>(_state: &'a mut S, _stage: &ST) -> Result<&'a mut Self, Error> {
        unimplemented!("NestedStageProgress should not be queried")
    }
}

#[derive(Debug)]
/// Perform the stage while the closure evaluates to true
pub struct WhileStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    closure: CB,
    stages: ST,
    phantom: PhantomData<(E, EM, Z)>,
}

impl<CB, E, EM, ST, Z> UsesState for WhileStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    type State = E::State;
}

impl<CB, E, EM, ST, Z> Stage<E, EM, Z> for WhileStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
    E::State: HasNestedStageStatus,
{
    type Progress = NestedStageProgress;

    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        while state.current_stage()?.is_some() || (self.closure)(fuzzer, executor, state, manager)?
        {
            self.stages.perform_all(fuzzer, executor, state, manager)?;
        }

        Ok(())
    }
}

impl<CB, E, EM, ST, Z> WhileStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    /// Constructor
    pub fn new(closure: CB, stages: ST) -> Self {
        Self {
            closure,
            stages,
            phantom: PhantomData,
        }
    }
}

/// A conditionally enabled stage.
/// If the closure returns true, the wrapped stage will be executed, else it will be skipped.
#[derive(Debug)]
pub struct IfStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    closure: CB,
    if_stages: ST,
    phantom: PhantomData<(E, EM, Z)>,
}

impl<CB, E, EM, ST, Z> UsesState for IfStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    type State = E::State;
}

impl<CB, E, EM, ST, Z> Stage<E, EM, Z> for IfStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
    E::State: HasNestedStageStatus,
{
    type Progress = NestedStageProgress;

    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        if state.current_stage()?.is_some() || (self.closure)(fuzzer, executor, state, manager)? {
            self.if_stages
                .perform_all(fuzzer, executor, state, manager)?;
        }
        Ok(())
    }
}

impl<CB, E, EM, ST, Z> IfStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    /// Constructor for this conditionally enabled stage.
    /// If the closure returns true, the wrapped stage will be executed, else it will be skipped.
    pub fn new(closure: CB, if_stages: ST) -> Self {
        Self {
            closure,
            if_stages,
            phantom: PhantomData,
        }
    }
}

/// Perform the stage if closure evaluates to true
#[derive(Debug)]
pub struct IfElseStage<CB, E, EM, ST1, ST2, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST1: StagesTuple<E, EM, E::State, Z>,
    ST2: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    closure: CB,
    if_stages: ST1,
    else_stages: ST2,
    phantom: PhantomData<(E, EM, Z)>,
}

impl<CB, E, EM, ST1, ST2, Z> UsesState for IfElseStage<CB, E, EM, ST1, ST2, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST1: StagesTuple<E, EM, E::State, Z>,
    ST2: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    type State = E::State;
}

impl<CB, E, EM, ST1, ST2, Z> Stage<E, EM, Z> for IfElseStage<CB, E, EM, ST1, ST2, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST1: StagesTuple<E, EM, E::State, Z>,
    ST2: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
    E::State: HasNestedStageStatus,
{
    type Progress = NestedStageProgress;

    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let current = state.current_stage()?;

        let fresh = current.is_none();
        let closure_return = fresh && (self.closure)(fuzzer, executor, state, manager)?;

        if current == Some(0) || closure_return {
            if fresh {
                state.set_stage(0)?;
            }
            state.enter_inner_stage()?;
            self.if_stages
                .perform_all(fuzzer, executor, state, manager)?;
        } else {
            if fresh {
                state.set_stage(1)?;
            }
            state.enter_inner_stage()?;
            self.else_stages
                .perform_all(fuzzer, executor, state, manager)?;
        }

        state.exit_inner_stage()?;
        state.clear_stage()?;

        Ok(())
    }
}

impl<CB, E, EM, ST1, ST2, Z> IfElseStage<CB, E, EM, ST1, ST2, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST1: StagesTuple<E, EM, E::State, Z>,
    ST2: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    /// Constructor
    pub fn new(closure: CB, if_stages: ST1, else_stages: ST2) -> Self {
        Self {
            closure,
            if_stages,
            else_stages,
            phantom: PhantomData,
        }
    }
}

/// A stage wrapper where the stages do not need to be initialized, but can be [`None`].
#[derive(Debug)]
pub struct OptionalStage<E, EM, ST, Z>
where
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    stages: Option<ST>,
    phantom: PhantomData<(E, EM, Z)>,
}

impl<E, EM, ST, Z> UsesState for OptionalStage<E, EM, ST, Z>
where
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    type State = E::State;
}

impl<E, EM, ST, Z> Stage<E, EM, Z> for OptionalStage<E, EM, ST, Z>
where
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
    E::State: HasNestedStageStatus,
{
    type Progress = NestedStageProgress;

    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        if let Some(stages) = &mut self.stages {
            stages.perform_all(fuzzer, executor, state, manager)
        } else {
            Ok(())
        }
    }
}

impl<E, EM, ST, Z> OptionalStage<E, EM, ST, Z>
where
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    /// Constructor for this conditionally enabled stage.
    #[must_use]
    pub fn new(stages: Option<ST>) -> Self {
        Self {
            stages,
            phantom: PhantomData,
        }
    }

    /// Constructor for this conditionally enabled stage with set stages.
    #[must_use]
    pub fn some(stages: ST) -> Self {
        Self {
            stages: Some(stages),
            phantom: PhantomData,
        }
    }

    /// Constructor for this conditionally enabled stage, without stages set.
    #[must_use]
    pub fn none() -> Self {
        Self {
            stages: None,
            phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod test {
    use core::{cell::RefCell, marker::PhantomData};

    use libafl_bolts::{tuples::tuple_list, Error};

    use crate::{
        inputs::NopInput,
        stages::{
            test::{test_resume, test_resume_stages},
            ClosureStage, IfElseStage, IfStage, Stage, WhileStage,
        },
        state::{test::test_std_state, State, UsesState},
    };

    #[test]
    fn check_resumability_while() {
        let once = RefCell::new(true);
        let (completed, stages) = test_resume_stages();
        let whilestage = WhileStage::new(|_, _, _, _| Ok(once.replace(false)), stages);
        let resetstage = ClosureStage::new(|_, _, _, _| {
            once.replace(true);
            Ok(())
        });

        let mut state = test_std_state::<NopInput>();

        test_resume(&completed, &mut state, tuple_list!(whilestage, resetstage));
    }

    #[test]
    fn check_resumability_if() {
        let once = RefCell::new(true);
        let (completed, stages) = test_resume_stages();
        let ifstage = IfStage::new(|_, _, _, _| Ok(once.replace(false)), stages);
        let resetstage = ClosureStage::new(|_, _, _, _| {
            once.replace(true);
            Ok(())
        });

        let mut state = test_std_state::<NopInput>();

        test_resume(&completed, &mut state, tuple_list!(ifstage, resetstage));
    }

    #[test]
    fn check_resumability_if_deep() {
        let (completed, stages) = test_resume_stages();
        let ifstage = IfStage::new(
            |_, _, _, _| Ok(true),
            tuple_list!(IfStage::new(
                |_, _, _, _| Ok(true),
                tuple_list!(IfStage::new(
                    |_, _, _, _| Ok(true),
                    tuple_list!(IfStage::new(
                        |_, _, _, _| Ok(true),
                        tuple_list!(IfStage::new(|_, _, _, _| Ok(true), stages),),
                    ),),
                ))
            )),
        );

        let mut state = test_std_state::<NopInput>();

        test_resume(&completed, &mut state, tuple_list!(ifstage));
    }

    #[derive(Debug)]
    pub struct PanicStage<S> {
        phantom: PhantomData<S>,
    }

    impl<S> PanicStage<S> {
        pub fn new() -> Self {
            Self {
                phantom: PhantomData,
            }
        }
    }

    impl<S> UsesState for PanicStage<S>
    where
        S: State,
    {
        type State = S;
    }

    impl<E, EM, Z> Stage<E, EM, Z> for PanicStage<E::State>
    where
        E: UsesState,
        EM: UsesState<State = E::State>,
        Z: UsesState<State = E::State>,
    {
        type Progress = ();

        fn perform(
            &mut self,
            _fuzzer: &mut Z,
            _executor: &mut E,
            _state: &mut Self::State,
            _manager: &mut EM,
        ) -> Result<(), Error> {
            panic!("Test failed; panic stage should never be executed.");
        }
    }

    #[test]
    fn check_resumability_if_else_if() {
        let once = RefCell::new(true);
        let (completed, stages) = test_resume_stages();
        let ifstage = IfElseStage::new(
            |_, _, _, _| Ok(once.replace(false)),
            stages,
            tuple_list!(PanicStage::new()),
        );
        let resetstage = ClosureStage::new(|_, _, _, _| {
            once.replace(true);
            Ok(())
        });

        let mut state = test_std_state::<NopInput>();

        test_resume(&completed, &mut state, tuple_list!(ifstage, resetstage));
    }

    #[test]
    fn check_resumability_if_else_else() {
        let once = RefCell::new(false);
        let (completed, stages) = test_resume_stages();
        let ifstage = IfElseStage::new(
            |_, _, _, _| Ok(once.replace(true)),
            tuple_list!(PanicStage::new()),
            stages,
        );
        let resetstage = ClosureStage::new(|_, _, _, _| {
            once.replace(false);
            Ok(())
        });

        let mut state = test_std_state::<NopInput>();

        test_resume(&completed, &mut state, tuple_list!(ifstage, resetstage));
    }

    #[test]
    fn check_resumability_if_else_else_deep() {
        let (completed, stages) = test_resume_stages();
        let ifstage = IfElseStage::new(
            |_, _, _, _| Ok(false),
            tuple_list!(PanicStage::new()),
            tuple_list!(IfElseStage::new(
                |_, _, _, _| Ok(false),
                tuple_list!(PanicStage::new()),
                tuple_list!(IfElseStage::new(
                    |_, _, _, _| Ok(false),
                    tuple_list!(PanicStage::new()),
                    tuple_list!(IfElseStage::new(
                        |_, _, _, _| Ok(false),
                        tuple_list!(PanicStage::new()),
                        tuple_list!(IfElseStage::new(
                            |_, _, _, _| Ok(false),
                            tuple_list!(PanicStage::new()),
                            stages,
                        )),
                    )),
                )),
            )),
        );

        let mut state = test_std_state::<NopInput>();

        test_resume(&completed, &mut state, tuple_list!(ifstage));
    }
}
