use graphviz_rust::{
    cmd::{CommandArg, Format},
    exec,
    printer::PrinterContext,
};

use std::fs::read_to_string;

use serde::Deserialize;

use toml::from_str;

use crate::answer::Answer;
use crate::utils::validate_input;

// Used to read the TOML file.
#[derive(Deserialize)]
pub struct QuestionList {
    question: Vec<Question>,
}

#[derive(Clone, Deserialize, PartialEq, Debug)]
pub struct Question {
    pub id: String,         // The id is resolved to local indexes.
    pub title: String,      // The question itself.
    pub content: String,    // Description related to the question, to help the user.
    pub skipped_by: String, // The question that skipped the current one.
    pub previous: String,   // The question that led to the current one.
    pub answers: Vec<Answer>,
}

impl Question {
    // Builds the diagram of questions from the toml file.
    // The diagram is a vector of Questions (vector of nodes): each Question, depending on the answer, will have the index of the next
    // Question that should be asked.
    pub fn new() -> Vec<Question> {
        let contents = read_to_string("questions.toml").expect("Failed to read questions file.");

        let q_list: QuestionList = from_str(&contents).expect("Failed to parse toml questions.");

        q_list.question
    }

    pub fn print_question(&self) {
        let mut output = String::new();

        // Construct the output string
        output.push_str(&format!(
            "+=====================+\n|    libafl wizard    |\n+=====================+\n\n"
        ));
        output.push_str(&format!("{}\n\n", self.title));
        output.push_str(&format!("{}\n\n\t", self.content));

        for ans in self.answers.iter() {
            output.push_str(&format!("{}{}", ans.answer, " ".repeat(8)));
        }

        output.push_str("Undo\n");

        print!("{}", output);
    }

    // Checks if the user typed one of the acceptable answers or is undoing.
    pub fn is_answer(&self, input: &String) -> bool {
        if input.is_empty() {
            return false;
        }

        for ans in self.answers.iter() {
            if validate_input(&input, &ans.answer) {
                return true;
            }
        }

        if validate_input(&input, &String::from("Undo")) {
            return true;
        }

        false
    }

    pub fn chosen_answer(&self) -> usize {
        for (i, ans) in self.answers.iter().enumerate() {
            if ans.was_chosen {
                return i;
            }
        }

        0
    }

    pub fn resolve_answer(&self, questions: &Vec<Question>, input: &String) -> (usize, usize) {
        // Checks which of the acceptable answers the user typed. If so, returns the index of the next question associated to it.
        for (i, ans) in self.answers.iter().enumerate() {
            if validate_input(&input, &ans.answer) {
                let mut next_q = find_question(questions, &ans.next);

                // If the question should be skipped, then the wizard goes to next question.
                // These types of questions should always have only one possibility for next question because the wizard cant infer
                // which answer the user would have chosen.
                while !questions[next_q].skipped_by.is_empty() {
                    next_q = find_question(questions, &ans.next);
                }

                return (next_q, i);
            }
        }

        (0, 0)
    }

    pub fn skip_questions(&self, questions: &mut Vec<Question>, ans_i: usize) {
        for q_id in self.answers[ans_i].skip.iter() {
            let i = questions
                .iter()
                .position(|question| &question.id == q_id)
                .unwrap();

            questions[i].skipped_by = self.id.clone();
        }
    }

    pub fn unskip_questions(&self, questions: &mut Vec<Question>, ans_i: usize) {
        for q_id in self.answers[ans_i].skip.iter() {
            let i = questions
                .iter()
                .position(|question| &question.id == q_id)
                .unwrap();

            questions[i].skipped_by.clear();
        }
    }

    pub fn update_previous(&mut self, q_id: String) -> () {
        // Saves the current questions as the previous for the next one.
        self.previous = q_id;
    }

    pub fn diff_next_questions(&self) -> bool {
        for (i, ans1) in self.answers.iter().enumerate() {
            for (j, ans2) in self.answers.iter().enumerate() {
                if i != j {
                    if ans1.next != ans2.next {
                        return true;
                    }
                }
            }
        }

        false
    }
}

// Resolves the index in the vector for the specific question.
pub fn find_question(questions: &Vec<Question>, q: &String) -> usize {
    questions
        .iter()
        .position(|question| &question.id == q)
        .unwrap()
}

// Requires 'graphviz' to be installed on the machine, or results in an error.
pub fn flowchart_image(questions: &Vec<Question>) {
    let mut dot_string = String::from("digraph t {\n");

    for q in questions {
        if q.id != "END" {
            dot_string.push_str(&format!("\t\"{}\"[color=black]\n", q.title));

            // CHANGE HERE
            if !q.diff_next_questions() {
                let j = questions
                    .iter()
                    .position(|question| &question.id == &q.answers[0].next)
                    .unwrap();

                // Yes or No questions that lead to the same next.
                if q.answers.len() <= 2 {
                    for ans in &q.answers {
                        dot_string.push_str(&format!(
                            "\t\"{}\" -> \"{}\"\n[label=\"{}\"]",
                            q.title, questions[j].title, ans.answer,
                        ));
                    }
                } else {
                    // Multiple answers that lead to the same next.
                    dot_string.push_str(&format!(
                        "\t\"{}\" -> \"{}\"\n[label=\"{}\"]",
                        q.title, questions[j].title, q.answers[0].answer,
                    ));

                    dot_string.push_str(&format!(
                        "\t\"{}\" -> \"{}\"\n[label=\"...\"]",
                        q.title, questions[j].title,
                    ));
                }
            }
            // Multiple answers that lead to distinct next questions.
            else {
                for ans in q.answers.iter() {
                    let j = questions
                        .iter()
                        .position(|question| question.id == ans.next)
                        .unwrap();

                    dot_string.push_str(&format!(
                        "\t\"{}\" -> \"{}\"\n[label=\"{}\"]",
                        q.title, questions[j].title, ans.answer,
                    ));
                }
            }
        } else {
            break;
        }
    }

    dot_string.push_str("}");

    let g = graphviz_rust::parse(&dot_string).unwrap();

    let mut ctx = PrinterContext::default();
    ctx.always_inline();

    let _graph_png = exec(
        g,
        &mut ctx,
        vec![
            CommandArg::Format(Format::Png),
            CommandArg::Output("flowchart.png".to_string()),
        ],
    )
    .unwrap();
}
