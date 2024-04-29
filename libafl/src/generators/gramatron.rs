//! Gramatron generator
use alloc::{string::String, vec::Vec};
use core::marker::PhantomData;

use libafl_bolts::rands::Rand;
use serde::{Deserialize, Serialize};

use crate::{
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
pub struct GramatronGenerator<'a, S>
where
    S: HasRand,
{
    automaton: &'a Automaton,
    phantom: PhantomData<S>,
}

impl<'a, S> Generator<GramatronInput, S> for GramatronGenerator<'a, S>
where
    S: HasRand,
{
    fn generate(&mut self, state: &mut S) -> Result<GramatronInput, Error> {
        let mut input = GramatronInput::new(vec![]);
        self.append_generated_terminals(&mut input, state);
        Ok(input)
    }
}

impl<'a, S> GramatronGenerator<'a, S>
where
    S: HasRand,
{
    /// Returns a new [`GramatronGenerator`]
    #[must_use]
    pub fn new(automaton: &'a Automaton) -> Self {
        Self {
            automaton,
            phantom: PhantomData,
        }
    }

    /// Append the generated terminals
    pub fn append_generated_terminals(&self, input: &mut GramatronInput, state: &mut S) -> usize {
        let mut counter = 0;
        let final_state = self.automaton.final_state;
        let mut current_state =
            input
                .terminals()
                .last()
                .map_or(self.automaton.init_state, |last| {
                    let triggers = &self.automaton.pda[last.state];
                    let idx = state.rand_mut().below(triggers.len());
                    triggers[idx].dest
                });

        while current_state != final_state {
            let triggers = &self.automaton.pda[current_state];
            let idx = state.rand_mut().below(triggers.len());
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
