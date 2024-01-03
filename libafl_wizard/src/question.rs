use graphviz_rust::{
    cmd::{CommandArg, Format},
    exec,
    printer::PrinterContext,
};
use serde::Deserialize;
use std::fs::read_to_string;
use toml::from_str;

use crate::answer::Answer;
use crate::utils::validate_input;

/// Used to read the TOML file containing the questions.
#[derive(Deserialize)]
pub struct QuestionList {
    question: Vec<Question>,
}

/// The Question struct contains all the necessary information that a question
/// must have, such as the title containing the question being asked and the set
/// of possible answers for this particular question.
#[derive(Clone, Deserialize, PartialEq, Debug)]
pub struct Question {
    id: String,
    title: String,
    content: String,
    skipped_by: String,
    previous: String,
    answers: Vec<Answer>,
}

impl Question {
    /// Reads the questions in the TOML file to a vector, where each field is an
    /// unique question.
    pub fn new() -> Vec<Question> {
        let contents = read_to_string("questions.toml").expect("Failed to read questions file.");

        let q_list: QuestionList = from_str(&contents).expect("Failed to parse toml questions.");

        q_list.question
    }

    /// Returns the id of the question, which is used to differentiate between
    /// questions.
    pub fn id(&self) -> String {
        self.id
    }

    /// Returns the title of the question, which in most cases is the questions
    /// being asked.
    ///
    /// The 'title' is also used as the text of the nodes in the flowchart
    /// image.
    pub fn title(&self) -> String {
        self.title
    }

    /// Returns the description of the question, usually some information to
    /// help the user understand the concepts associated with a particular
    /// question.
    pub fn content(&self) -> String {
        self.content
    }

    /// Returns the id of the question that skipped the one under consideration.
    pub fn skipped_by(&self) -> String {
        self.skipped_by
    }

    /// Sets that this particular question was skipped by the one with this id.
    pub fn set_skipped_by(&self, id: String) {
        self.skipped_by = id;
    }

    /// Returns the id of the question that led to the current one.
    pub fn previous(&self) -> String {
        self.previous
    }

    /// Sets that this particular question came after the one with this id was
    /// answered.
    pub fn set_previous(&self, id: String) {
        self.previous = id;
    }

    /// Returns the set of possible answers for this question, excluding the
    /// Undo option.
    pub fn answers(&self) -> Vec<Answer> {
        self.answers
    }

    /// Prints all the relevant information of this question.
    pub fn print_question(&self) {
        let mut output = String::new();

        // Construct the output string
        output.push_str(&format!(
            "+=====================+\n|    libafl_wizard    |\n+=====================+\n\n"
        ));
        output.push_str(&format!("{}\n\n", self.title()));
        output.push_str(&format!("{}\n\n\t", self.content()));

        for ans in self.answers().iter() {
            output.push_str(&format!(
                "{}{}|{}",
                ans.answer(),
                " ".repeat(4),
                " ".repeat(4)
            ));
        }

        output.push_str("Undo\n");

        print!("{}", output);
    }

    /// Checks if the user typed one of the acceptable answers or is undoing.
    pub fn is_answer(&self, input: &String) -> bool {
        if input.is_empty() {
            return false;
        } else if validate_input(&input, &String::from("Undo")) {
            return true;
        }

        for ans in self.answers().iter() {
            if validate_input(&input, &ans.answer()) {
                return true;
            }
        }

        false
    }

    /// Returns the index of the chosen answer in the vector of possible answer
    /// for this given question.
    pub fn chosen_answer(&self) -> usize {
        for (i, ans) in self.answers().iter().enumerate() {
            if ans.was_chosen() {
                return i;
            }
        }

        0
    }

    /// Returns a tuple containing the id of the next question and the index of
    /// answer chosen for this question.
    ///
    /// If an invalid answer is provided, the function returns 0 as default for
    /// both values.
    pub fn resolve_answer(&self, questions: &Vec<Question>, input: &String) -> (usize, usize) {
        // Checks which of the acceptable answers the user typed. If so, returns the index of the next question associated to it.
        for (i, ans) in self.answers().iter().enumerate() {
            if validate_input(&input, &ans.answer()) {
                let mut next_q = find_question(questions, &ans.next());

                // If the question should be skipped, then the wizard goes to next question.
                // These types of questions should always have only one possibility for next question because the wizard cant infer
                // which answer the user would have chosen.
                while !questions[next_q].skipped_by().is_empty() {
                    next_q = find_question(questions, &ans.next());
                }

                return (next_q, i);
            }
        }

        (0, 0)
    }

    /// Marks the questions to be skipped.
    pub fn skip_questions(&self, questions: &mut Vec<Question>, ans_i: usize) {
        let answers = self.answers();

        for q_id in answers[ans_i].skip().iter() {
            let i = questions
                .iter()
                .position(|question| &question.id() == q_id)
                .unwrap();

            questions[i].set_skipped_by(self.id().clone());
        }
    }

    /// Unmarks the questions that would be skipped.
    pub fn unskip_questions(&self, questions: &mut Vec<Question>, ans_i: usize) {
        let answers = self.answers();

        for q_id in answers[ans_i].skip().iter() {
            let i = questions
                .iter()
                .position(|question| &question.id() == q_id)
                .unwrap();

            questions[i].set_skipped_by("".to_string());
        }
    }

    /// Returns true if, for the given set of answers for this question, at
    /// least one leads to a different next question than the others.
    pub fn diff_next_questions(&self) -> bool {
        for (i, ans1) in self.answers().iter().enumerate() {
            for (j, ans2) in self.answers().iter().enumerate() {
                if i != j {
                    if ans1.next() != ans2.next() {
                        return true;
                    }
                }
            }
        }

        false
    }
}

/// Returns the index of the question in the questions vector that has id == q.
pub fn find_question(questions: &Vec<Question>, q: &String) -> usize {
    questions
        .iter()
        .position(|question| &question.id() == q)
        .unwrap()
}

/// Generates an image containg the flowchart of the questions of the wizard.
///
/// Requires 'graphviz' to be installed on the machine, or panics.
pub fn flowchart_image(questions: &Vec<Question>) {
    let mut dot_string = String::from("digraph t {\n");

    for q in questions {
        if q.id() != "END" {
            dot_string.push_str(&format!("\t\"{}\"[color=black]\n", q.title()));

            if !q.diff_next_questions() {
                let j = questions
                    .iter()
                    .position(|question| &question.id() == &q.answers[0].next())
                    .unwrap();

                // Yes or No questions that lead to the same next.
                if q.answers().len() <= 2 {
                    for ans in &q.answers() {
                        dot_string.push_str(&format!(
                            "\t\"{}\" -> \"{}\"\n[label=\"{}\"]",
                            q.title(),
                            questions[j].title(),
                            ans.answer(),
                        ));
                    }
                } else {
                    // Multiple answers that lead to the same next.
                    dot_string.push_str(&format!(
                        "\t\"{}\" -> \"{}\"\n[label=\"{}\"]",
                        q.title(),
                        questions[j].title(),
                        q.answers[0].answer(),
                    ));

                    dot_string.push_str(&format!(
                        "\t\"{}\" -> \"{}\"\n[label=\"...\"]",
                        q.title(),
                        questions[j].title(),
                    ));
                }
            }
            // Multiple answers that lead to distinct next questions.
            else {
                for ans in q.answers().iter() {
                    let j = questions
                        .iter()
                        .position(|question| question.id() == ans.next())
                        .unwrap();

                    dot_string.push_str(&format!(
                        "\t\"{}\" -> \"{}\"\n[label=\"{}\"]",
                        q.title(),
                        questions[j].title(),
                        ans.answer(),
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
