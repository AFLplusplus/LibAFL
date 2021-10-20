use alloc::{string::String, vec::Vec};
use core::marker::PhantomData;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::rands::Rand,
    generators::Generator,
    inputs::{GramatronInput, Terminal},
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
pub struct GramatronGenerator<R, S>
where
    R: Rand,
    S: HasRand<R>,
{
    automaton: Automaton,
    phantom: PhantomData<(R, S)>,
}

impl<R, S> Generator<GramatronInput, S> for GramatronGenerator<R, S>
where
    R: Rand,
    S: HasRand<R>,
{
    fn generate(&mut self, state: &mut S) -> Result<GramatronInput, Error> {
        let mut input = GramatronInput::new(vec![]);
        self.append_generated_terminals(&mut input, state);
        Ok(input)
    }

    fn generate_dummy(&self, _state: &mut S) -> GramatronInput {
        GramatronInput::new(vec![])
    }
}

impl<R, S> GramatronGenerator<R, S>
where
    R: Rand,
    S: HasRand<R>,
{
    /// Returns a new [`GramatronGenerator`]
    #[must_use]
    pub fn new(automaton: Automaton) -> Self {
        Self {
            automaton,
            phantom: PhantomData,
        }
    }

    pub fn append_generated_terminals(&self, input: &mut GramatronInput, state: &mut S) -> usize {
        let mut counter = 0;
        let final_state = self.automaton.final_state;
        let mut current_state = input
            .terminals()
            .last()
            .map_or(self.automaton.init_state, |last| last.state);

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
