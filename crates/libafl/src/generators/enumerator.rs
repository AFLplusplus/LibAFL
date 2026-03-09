//! Enumerator for context-free grammar
use alloc::vec::Vec;

/// for more detail see the paper `https://arxiv.org/pdf/2305.00522`
use crate::generators::gramatron::Automaton;
use crate::inputs::Terminal;

/// IntegerizedStack encodes a stack of integers as a single integer.
#[derive(Debug)]
pub struct IntegerizedStack {
    value: u64,
}

impl IntegerizedStack {
    /// Create a new IntegerizedStack with initial value
    pub fn new(v: u64) -> Self {
        Self { value: v }
    }

    /// Removes an integer from self.value
    pub fn pop(&mut self) -> u64 {
        let (rest, ret) = decode(self.value);
        self.value = rest;
        ret
    }

    /// Pop from self.value mod n
    pub fn modpop(&mut self, modulus: u64) -> u64 {
        let (rest, ret) = mod_decode(self.value, modulus);
        self.value = rest;
        ret
    }

    /// Assumes value codes exactly n integers. Zero afterwards.
    pub fn split(&mut self, n: usize) -> Vec<u64> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..(n - 1) {
            out.push(self.pop());
        }
        out.push(self.value);
        self.value = 0;
        out
    }
}

/// Rosenberg-Strong pairing decode
fn decode(z: u64) -> (u64, u64) {
    let m = (z as f64).sqrt().floor() as u64;
    let msq = m * m;
    if z - msq < m {
        (z - msq, m)
    } else {
        (m, msq + 2 * m - z)
    }
}

/// Modular pairing decode
/// Returns (z mod k, (z - (z mod k)) / k)
fn mod_decode(z: u64, k: u64) -> (u64, u64) {
    let a = z % k;
    let b = (z - a) / k;
    (b, a)
}

/// Enumerate the n-th derivation directly on a Gramatron [`Automaton`]
/// - Triggers whose `dest` equals `final_state` are treated as terminal rules (base cases).
/// - All other triggers are nonterminal rules (recursive cases).
pub fn enumerate_automaton(state: usize, n: u64, automaton: &Automaton) -> Vec<Terminal> {
    let final_state = automaton.final_state;
    let triggers = &automaton.pda[state];

    // Partitioning triggers into terminals and nonterminals
    let terminal_indices: Vec<usize> = triggers
        .iter()
        .enumerate()
        .filter(|(_, t)| t.dest == final_state)
        .map(|(i, _)| i)
        .collect();
    let nonterminal_indices: Vec<usize> = triggers
        .iter()
        .enumerate()
        .filter(|(_, t)| t.dest != final_state)
        .map(|(i, _)| i)
        .collect();

    let num_terminal = terminal_indices.len() as u64;

    if n < num_terminal {
        // Base case: pick the n-th terminal trigger
        let trigger_idx = terminal_indices[n as usize];
        let trigger = &triggers[trigger_idx];
        return vec![Terminal::new(state, trigger_idx, trigger.term.clone())];
    }

    // if nonterminals then we need to choose one and recurse
    let mut stack = IntegerizedStack::new(n - num_terminal);
    let num_nonterminal = nonterminal_indices.len() as u64;
    let rule_choice = stack.modpop(num_nonterminal) as usize;
    let trigger_idx = nonterminal_indices[rule_choice];
    let trigger = &triggers[trigger_idx];
    let dest = trigger.dest;

    let mut result = vec![Terminal::new(state, trigger_idx, trigger.term.clone())];

    let child_terminals = enumerate_automaton(dest, stack.value, automaton);
    result.extend(child_terminals);
    result
}

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use super::*;
    use crate::generators::gramatron::Trigger;

    /// Build a test automaton with two recursive paths:
    ///
    /// ```text
    /// State 0 (init): "a"→3(final), "("→1, "["→2
    /// State 1:        ")"→3(final), "x"→1
    /// State 2:        "]"→3(final), "y"→2
    /// State 3 (final)
    /// ```
    ///
    /// This generates: "a", "()", "[]", "(x)", "[y]", "(xx)", "[yy]", ...
    fn test_automaton() -> Automaton {
        Automaton {
            init_state: 0,
            final_state: 3,
            pda: alloc::vec![
                // State 0
                alloc::vec![
                    Trigger {
                        dest: 3,
                        term: String::from("a")
                    },
                    Trigger {
                        dest: 1,
                        term: String::from("(")
                    },
                    Trigger {
                        dest: 2,
                        term: String::from("[")
                    },
                ],
                // State 1
                alloc::vec![
                    Trigger {
                        dest: 3,
                        term: String::from(")")
                    },
                    Trigger {
                        dest: 1,
                        term: String::from("x")
                    },
                ],
                // State 2
                alloc::vec![
                    Trigger {
                        dest: 3,
                        term: String::from("]")
                    },
                    Trigger {
                        dest: 2,
                        term: String::from("y")
                    },
                ],
                // State 3 (final)
                alloc::vec![],
            ],
        }
    }

    /// Helper: concatenate all terminal symbols into a single string.
    fn symbols_to_string(terms: &[Terminal]) -> String {
        terms.iter().map(|t| t.symbol.as_str()).collect()
    }

    #[test]
    fn test_enumerate_automaton_known_outputs() {
        let automaton = test_automaton();

        // n=0: terminal trigger at init → "a"
        let terms = enumerate_automaton(0, 0, &automaton);
        assert_eq!(symbols_to_string(&terms), "a");

        // n=1: "(" then recurse into state 1 depth 0 → "()"
        let terms = enumerate_automaton(0, 1, &automaton);
        assert_eq!(symbols_to_string(&terms), "()");

        // n=2: "[" then recurse into state 2 depth 0 → "[]"
        let terms = enumerate_automaton(0, 2, &automaton);
        assert_eq!(symbols_to_string(&terms), "[]");

        // n=3: "(" then "x" then ")" → "(x)"
        let terms = enumerate_automaton(0, 3, &automaton);
        assert_eq!(symbols_to_string(&terms), "(x)");

        // n=4: "[" then "y" then "]" → "[y]"
        let terms = enumerate_automaton(0, 4, &automaton);
        assert_eq!(symbols_to_string(&terms), "[y]");

        // n=5: "(" then "xx" then ")" → "(xx)"
        let terms = enumerate_automaton(0, 5, &automaton);
        assert_eq!(symbols_to_string(&terms), "(xx)");

        // n=6: "[" then "yy" then "]" → "[yy]"
        let terms = enumerate_automaton(0, 6, &automaton);
        assert_eq!(symbols_to_string(&terms), "[yy]");
    }
}
