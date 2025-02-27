extern crate alloc;

use alloc::{collections::VecDeque, rc::Rc};
use std::{
    collections::HashSet,
    fs,
    io::{BufReader, Write},
    path::{Path, PathBuf},
    sync::OnceLock,
};

use clap::Parser;
use libafl::generators::gramatron::{Automaton, Trigger};
use regex::Regex;
use serde_json::Value;

static RE: OnceLock<Regex> = OnceLock::new();

#[derive(Debug, Parser)]
#[command(
    name = "construct_automata",
    about = "Generate a serialized Automaton using a json GNF grammar",
    author = "Andrea Fioraldi <andreafioraldi@gmail.com>"
)]
struct Opt {
    #[arg(
        short,
        long = "grammar-file",
        name = "GRAMMAR",
        help = "The grammar to use during fuzzing"
    )]
    grammar: PathBuf,

    #[arg(
        short,
        long,
        name = "LIMIT",
        help = "The max stack size after which a generated input is abandoned",
        default_value = "0"
    )]
    limit: usize,

    #[arg(short, long, help = "Set the output file", name = "OUTPUT")]
    output: PathBuf,
}

fn read_grammar_from_file<P: AsRef<Path>>(path: P) -> Value {
    let file = fs::File::open(path).unwrap();
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).unwrap()
}

#[derive(Debug)]
struct Element<'src> {
    pub state: usize,
    pub items: Rc<VecDeque<&'src str>>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash)]
struct Transition<'src> {
    pub source: usize,
    pub dest: usize,
    // pub ss: Vec<String>,
    pub terminal: &'src str,
    // pub is_regex: bool,
    pub stack_len: usize,
}

#[derive(Default)]
struct Stacks<'src> {
    pub q: Vec<Rc<VecDeque<&'src str>>>,
    pub s: Vec<Box<[&'src str]>>,
}

fn tokenize(rule: &str) -> (&str, Vec<&str>) {
    let re = RE.get_or_init(|| Regex::new(r"([r])*'([\s\S]+)'([\s\S]*)").unwrap());
    // let re = RE.get_or_init(|| Regex::new(r"'([\s\S]+)'([\s\S]*)").unwrap());
    let cap = re.captures(rule).unwrap();
    // let is_regex = cap.get(1).is_some();
    let terminal = cap.get(2).unwrap().as_str();
    let ss = cap.get(3).map_or(vec![], |m| {
        m.as_str()
            .split_whitespace()
            // .map(ToOwned::to_owned)
            .collect()
    });
    if terminal == "\\n" {
        ("\n", ss /*is_regex*/)
    } else {
        (terminal, ss /*is_regex*/)
    }
}

fn prepare_transitions<'pda, 'src: 'pda>(
    grammar: &'src Value,
    pda: &'pda mut Vec<Transition<'src>>,
    state_stacks: &mut Stacks<'src>,
    state_count: &mut usize,
    worklist: &mut VecDeque<Element<'src>>,
    element: &Element,
    stack_limit: usize,
) {
    if element.items.is_empty() {
        return; // Final state was encountered, pop from worklist without doing anything
    }

    let state = element.state;
    let nonterminal = element.items[0];
    let rules = grammar[nonterminal].as_array().unwrap();
    // let mut i = 0;
    'rules_loop: for rule in rules {
        let rule = rule.as_str().unwrap();
        let (terminal, ss /*_is_regex*/) = tokenize(rule);
        let dest = *state_count;

        // log::trace!("Rule \"{}\", {} over {}", &rule, i, rules.len());

        // Creating a state stack for the new state
        let mut state_stack = state_stacks
            .q
            .get(state.wrapping_sub(1))
            .map_or(VecDeque::new(), |state_stack| (**state_stack).clone());

        state_stack.pop_front();
        for symbol in ss.into_iter().rev() {
            state_stack.push_front(symbol);
        }
        let mut state_stack_sorted: Box<[&str]> = state_stack.iter().copied().collect();
        state_stack_sorted.sort_unstable();

        let mut transition = Transition {
            source: state,
            dest,
            // ss,
            terminal,
            // is_regex,
            // stack: Rc::new(state_stack.clone()),
            stack_len: state_stack.len(),
        };

        // Check if a recursive transition state being created, if so make a backward
        // edge and don't add anything to the worklist
        for (dest, stack) in state_stacks.s.iter().enumerate() {
            if state_stack_sorted == *stack {
                transition.dest = dest + 1;
                // i += 1;
                pda.push(transition);

                // If a recursive transition exercised don't add the same transition as a new
                // edge, continue onto the next transitions
                continue 'rules_loop;
            }
        }

        // If the generated state has a stack size > stack_limit then that state is abandoned
        // and not added to the FSA or the worklist for further expansion
        if stack_limit > 0 && transition.stack_len > stack_limit {
            // TODO add to unexpanded_rules
            continue;
        }

        let state_stack = Rc::new(state_stack);

        // Create transitions for the non-recursive relations and add to the worklist
        worklist.push_back(Element {
            state: dest,
            items: Rc::clone(&state_stack),
        });

        // since each index corresponds to `state_count - 1`
        // index with `dest - 1`
        state_stacks.q.push(state_stack);
        state_stacks.s.push(state_stack_sorted);
        pda.push(transition);

        println!("worklist size: {}", worklist.len());

        *state_count += 1;
        // i += 1;
    }
}

fn get_states(pda: &[Transition]) -> (HashSet<usize>, HashSet<usize>, HashSet<usize>) {
    let mut source = HashSet::new();
    let mut dest = HashSet::new();
    for transition in pda {
        source.insert(transition.source);
        dest.insert(transition.dest);
    }
    let all = source.union(&dest).copied().collect();
    (
        all,
        dest.difference(&source).copied().collect(),
        source.difference(&dest).copied().collect(),
    )
}

fn postprocess(pda: &[Transition], stack_limit: usize) -> Automaton {
    let mut num_transition = 0;
    let (states, finals, initial) = get_states(pda);

    assert!(initial.len() == 1);

    println!("# transitions: {}", pda.len());
    println!("# states: {}", states.len());
    println!("initial state: {:?}", &initial);
    println!("final states: {:?}", &finals);

    let mut memoized = Vec::with_capacity(states.len());
    //let mut memoized_unique = Vec::with_capacity(states.len());

    // if stack_limit ...
    if stack_limit > 0 {
        let mut culled_pda = Vec::with_capacity(pda.len());
        let mut blocklist = HashSet::new();
        // let mut culled_pda_unique = HashSet::new();

        for final_state in &finals {
            for transition in pda {
                if transition.dest == *final_state && transition.stack_len > 0 {
                    blocklist.insert(transition.dest);
                } else {
                    culled_pda.push(transition);
                    //culled_pda_unique.insert(transition);
                }
            }
        }

        // log::trace!("culled_pda size: {} pda size: {}", culled_pda.len(), pda.len());

        let culled_finals: HashSet<usize> = finals.difference(&blocklist).copied().collect();
        assert!(culled_finals.len() == 1);

        let culled_pda_len = culled_pda.len();

        for transition in culled_pda {
            if blocklist.contains(&transition.dest) {
                continue;
            }
            num_transition += 1;
            let state = transition.source;
            if state >= memoized.len() {
                memoized.resize(state + 1, vec![]);
            }
            memoized[state].push(Trigger {
                dest: transition.dest,
                term: transition.terminal.to_string(),
            });

            if num_transition % 4096 == 0 {
                println!("processed {num_transition} transitions over {culled_pda_len}",);
            }
        }

        /*
        culled_pda_unique.iter().for_each(|transition| {
            if blocklist.contains(&transition.dest) {
                return;
            }
            num_transition += 1;
            let state = transition.source;
            if state >= memoized_unique.len() {
                memoized_unique.resize(state +1, vec![]);
            }
            memoized_unique[state].push(Trigger {dest: transition.dest, term: transition.terminal.clone()});
        });
        */

        Automaton {
            init_state: initial.into_iter().next().unwrap(),
            final_state: culled_finals.into_iter().next().unwrap(),
            pda: memoized,
        }
    } else {
        // Running FSA construction in exact approximation mode and postprocessing it like so
        for transition in pda {
            num_transition += 1;
            let state = transition.source;
            if state >= memoized.len() {
                memoized.resize(state + 1, vec![]);
            }
            memoized[state].push(Trigger {
                dest: transition.dest,
                term: transition.terminal.to_string(),
            });

            if num_transition % 4096 == 0 {
                println!(
                    "processed {} transitions over {}",
                    num_transition,
                    pda.len()
                );
            }
        }

        Automaton {
            init_state: initial.into_iter().next().unwrap(),
            final_state: finals.into_iter().next().unwrap(),
            pda: memoized,
        }
    }
}

fn main() {
    let opt = Opt::parse();

    let grammar_file = opt.grammar;
    let output_file = opt.output;
    let stack_limit = opt.limit;

    let mut worklist = VecDeque::new();
    let mut state_count = 1;
    let mut state_stacks = Stacks::default();
    let mut pda = vec![];

    let grammar = read_grammar_from_file(grammar_file);
    let start_symbol = grammar["Start"][0].as_str().unwrap();
    let mut start_vec = VecDeque::new();
    start_vec.push_back(start_symbol);
    worklist.push_back(Element {
        state: 0,
        items: Rc::new(start_vec),
    });

    while let Some(element) = worklist.pop_front() {
        prepare_transitions(
            &grammar,
            &mut pda,
            &mut state_stacks,
            &mut state_count,
            &mut worklist,
            &element,
            stack_limit,
        );
    }

    drop(state_stacks);

    let transformed = postprocess(&pda, stack_limit);
    let serialized = postcard::to_allocvec(&transformed).unwrap();

    let mut file = fs::File::create(output_file).unwrap();
    file.write_all(&serialized).unwrap();
}
