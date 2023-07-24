use serde::Deserialize;
use std::{error::Error, fmt, fs};
use toml;

// Used to read the TOML file
#[derive(Deserialize)]
struct QuestionList {
    question: Vec<Question>,
}

// This reresents a "node": the answer of a Question might lead to different Questions (different nodes).
#[derive(Clone, Deserialize)]
pub struct Question {
    name: String,         // The question that will be asked.
    content: String,      // Description related to the question, to help the user.
    answers: Vec<String>, // A vector containing all the possible answers for this question.
    next: Vec<usize>, // A vector containing the next question for all the possible answers (for answer[0] the next question is next[0]...).
    previous: usize, // The question that lead to the current one (possible UNDO functionality implementation).
    code: String,    // Contains the Rust code associated to the question
}

impl Question {
    // Builds the diagram of questions from the csv file (this will probably be changed, the csv is used only for demonstrative purposes).
    // The diagram is a vector of Questions (vector of nodes): each Question, depending on the answer, will have the index of the next Question
    // that should be asked.
    pub fn new() -> Result<Vec<Question>, Box<dyn Error>> {
        let contents = fs::read_to_string("questions.toml")?;

        let q_list: QuestionList = toml::from_str(&contents)?;

        // Checks if each question is valid.
        for q in q_list.question.iter() {
            q.validate_question()?;
        }

        Ok(q_list.question)
    }

    pub fn validate_question(&self) -> Result<(), Box<dyn Error>> {
        // At least one possible answer.
        if self.answers.len() <= 0 {
            return Err(Box::new(ZeroAnswersError(
                "Error: Question with 0 answers found.\n".into(),
            )));
        }

        // The number of answers has to match the number of next questions.
        if self.answers.len() != self.next.len() {
            return Err(Box::new(DiffNumOfAnswersAndNextError(
                "Error: The number of answers in a question doesn't match the number of next questions.\n".into(),
            )));
        }

        Ok(())
    }

    pub fn print_question(&self) -> () {
        print!("{esc}c", esc = 27 as char);
        println!("=========================\nFuzzer Template Generator\n=========================");
        println!("{}\n", self.name);
        println!("{}\n", self.content);

        for ans in &self.answers {
            print!("\t{}", ans);
        }

        println!("\tUndo");
    }

    // Checks if the answer given by the user is one of the possibilities that the generator expects.
    pub fn validate_answer(&self, input: &mut String) -> bool {
        if input.ends_with("\r\n") {
            input.truncate(input.len() - 2);
        } else if input.ends_with("\n") {
            input.truncate(input.len() - 1);
        }

        // The "Undo" option makes the generator go back to the previous question, so if the user do something by mistake, they can correct it.
        if input == "Undo" {
            return true;
        }

        // Checks if the user typed one of the acceptable answers.
        // For now we dont check for variants (with the implementation of an interface this wont be necessary).
        for ans in &self.answers {
            if input == ans {
                return true;
            }
        }

        false
    }

    pub fn next_question(
        &self,
        q_diagram: &mut Vec<Question>,
        input: &String,
        q_index: usize,
    ) -> usize {
        if input == "Undo" {
            return self.previous;
        }

        // Checks which of the acceptable answers the user chose, then sets the 'previous' field for the next question as the current one and
        // returns the index of the next question.
        for (i, ans) in self.answers.iter().enumerate() {
            if input == ans {
                q_diagram[self.next[i]].previous = q_index;
                return self.next[i];
            }
        }

        // The compiler complained about the base case so I'll probably change the logic of this method.
        self.next[0]
    }
}

// Custom error types
#[derive(Debug)]
pub struct ZeroAnswersError(pub String);

impl fmt::Display for ZeroAnswersError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for ZeroAnswersError {}

#[derive(Debug)]
pub struct DiffNumOfAnswersAndNextError(pub String);

impl fmt::Display for DiffNumOfAnswersAndNextError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for DiffNumOfAnswersAndNextError {}
