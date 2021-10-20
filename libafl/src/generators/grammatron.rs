use alloc::{string::String, vec::Vec};
use core::marker::PhantomData;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::rands::Rand,
    generators::Generator,
    inputs::{GrammatronInput, Terminal},
    state::HasRand,
    Error,
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Trigger {
    pub id: String,
    pub dest: usize,
    pub term: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Automaton {
    pub final_state: usize,
    pub init_state: usize,
    pub pda: Vec<Vec<Trigger>>,
}

#[derive(Clone, Debug)]
/// Generates random inputs from a grammar automatron
pub struct GrammatronGenerator<R, S>
where
    R: Rand,
    S: HasRand<R>,
{
    automaton: Automaton,
    phantom: PhantomData<(R, S)>,
}

impl<R, S> Generator<GrammatronInput, S> for GrammatronGenerator<R, S>
where
    R: Rand,
    S: HasRand<R>,
{
    fn generate(&mut self, state: &mut S) -> Result<GrammatronInput, Error> {
        let mut input = GrammatronInput::new(vec![]);
        self.append_generated_terminals(&mut input, state);
        Ok(input)
    }

    fn generate_dummy(&self, _state: &mut S) -> GrammatronInput {
        GrammatronInput::new(vec![])
    }
}

impl<R, S> GrammatronGenerator<R, S>
where
    R: Rand,
    S: HasRand<R>,
{
    /// Returns a new [`GrammatronGenerator`]
    #[must_use]
    pub fn new(automaton: Automaton) -> Self {
        Self {
            automaton,
            phantom: PhantomData,
        }
    }

    pub fn append_generated_terminals(&self, input: &mut GrammatronInput, state: &mut S) -> usize {
        let mut counter = 0;
        let final_state = self.automaton.final_state;
        let mut current_state = if let Some(last) = input.terminals().last() {
            last.state
        } else {
            self.automaton.init_state
        };

        while current_state != final_state {
            let triggers = &self.automaton.pda[current_state];
            let idx = state.rand_mut().below(triggers.len() as u64) as usize;
            let trigger = &triggers[idx];
            input
                .terminals_mut()
                .push(Terminal::new(current_state, idx, trigger.term.clone()));
            current_state = trigger.dest;
            counter += 1;
        }

        counter
    }
}
