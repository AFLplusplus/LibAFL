use serde::Deserialize;

#[derive(Clone, Deserialize, PartialEq, Debug)]
pub struct Answer {
    pub was_chosen: bool, // Used when undoing.
    pub answer: String,
    pub next: String,      // The next question if this answer is chosen.
    pub code: String,      // The code added to the file.
    pub skip: Vec<String>, // The questions to skip.
}

impl Answer {
    pub fn has_code(&self) -> bool {
        if !self.code.is_empty() {
            return true;
        }

        false
    }

    pub fn add_code(&self, code_content: &mut Vec<String>) {
        if !self.code.is_empty() {
            code_content.push(self.code.to_string());
        }
    }
}
