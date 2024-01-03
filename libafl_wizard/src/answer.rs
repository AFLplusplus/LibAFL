use serde::Deserialize;

/// The Answer struct contains all the necessary information that an answer must
/// have, such as the code to be added and the next question to be asked.
#[derive(Clone, Deserialize, PartialEq, Debug)]
pub struct Answer {
    was_chosen: bool,
    answer: String,
    next: String,
    code: String,
    skip: Vec<String>,
}

impl Answer {
    /// Returns true if this answer was chosen between all the possibilities for
    /// a given question.
    pub fn was_chosen(&self) -> bool {
        self.was_chosen
    }

    /// Returns true if this answer was chosen between all the possibilities for
    /// a given question.
    pub fn set_was_chosen(&self, new_value: bool) {
        self.was_chosen = new_value;
    }

    /// Returns a String that represents the text of that answer, e.g "Yes" or
    /// "No".
    pub fn answer(&self) -> String {
        self.answer
    }

    /// Returns the id of the next question that will be asked, considering that
    /// this answer was chosen.
    pub fn next(&self) -> String {
        self.next
    }

    /// Returns the Rust code that will be added to the fuzzer file, considering
    /// that this answer was chosen.
    pub fn code(&self) -> String {
        self.code
    }

    /// Returns the ids of the questions that should be skipped, considering
    /// that this answer was chosen.
    ///
    /// In some cases, depending on the answer that the user chooses for a
    /// particular question, it will skip other questions that shouldn't be
    /// asked, e.g. if the user doesn't have the source code of the that target
    /// the wizard shouldn't ask if they can provide a harness.
    pub fn skip(&self) -> Vec<String> {
        self.skip
    }
}
