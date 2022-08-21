//! Gramatron generator
use alloc::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};

use crate::{
    bolts::rands::Rand,
    generators::Generator,
    inputs::{GramatronInput, Terminal},
    state::HasRand,
    Error,
};

/// A trigger
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Trigger {
    /// the destination
    pub dest: usize,
    /// the term
    pub term: String,
}

/// The [`Automaton`]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Automaton {
    /// final state
    pub final_state: usize,
    /// init state
    pub init_state: usize,
    /// pda of [`Trigger`]s
    pub pda: Vec<Vec<Trigger>>,
}

#[derive(Clone, Debug)]
/// Generates random inputs from a grammar automaton
pub struct GramatronGenerator<'a> {
    automaton: &'a Automaton,
}

impl<'a> Generator for GramatronGenerator<'a>
where
    Self: Generator<Input = GramatronInput>,
    Self::State: HasRand,
{
    fn generate(&mut self, state: &mut Self::State) -> Result<GramatronInput, Error> {
        let mut input = GramatronInput::new(vec![]);
        self.append_generated_terminals(&mut input, state);
        Ok(input)
    }

    fn generate_dummy(&self, _state: &mut Self::State) -> GramatronInput {
        GramatronInput::new(vec![])
    }
}

impl<'a> GramatronGenerator<'a>
where
    <Self as Generator>::State: HasRand,
{
    /// Returns a new [`GramatronGenerator`]
    #[must_use]
    pub fn new(automaton: &'a Automaton) -> Self {
        Self { automaton }
    }

    /// Append the generated terminals
    pub fn append_generated_terminals(
        &self,
        input: &mut GramatronInput,
        state: &mut <Self as Generator>::State,
    ) -> usize {
        let mut counter = 0;
        let final_state = self.automaton.final_state;
        let mut current_state =
            input
                .terminals()
                .last()
                .map_or(self.automaton.init_state, |last| {
                    let triggers = &self.automaton.pda[last.state];
                    let idx = state.rand_mut().below(triggers.len() as u64) as usize;
                    triggers[idx].dest
                });

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
