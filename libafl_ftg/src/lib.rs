use std::error::Error;

// Used to copy the fields of a question.
type QuestionTup = (String, String, String, String, usize, usize, usize);

// This reresents a "node": the answer of a Question might lead to different Questions (different nodes).
#[derive(Clone)]
pub struct Question {
    name: String,    // The question that will be asked.
    content: String, // Description related to the question, to help the user.
    answer1: String, // One of the possible answers that may result, either in another question, or a component.
    answer2: String, // Same.
    next1: usize, // The next question (or the choice of an specific component), if answer1 is chosen.
    next2: usize, // The next question (or the choice of an specific component), if answer2 is chosen.
    previous: usize, // The question that lead to the current one (possible UNDO functionality implementation).
}

impl Question {
    // Builds the diagram of questions from the csv file (this will probably be changed, the csv is used only for demonstrative purposes).
    // The diagram is a vector of Questions (vector of nodes): each Question, depending on the answer, will have the index of the next Question
    // that should be asked.
    pub fn new() -> Result<Vec<Question>, Box<dyn Error>> {
        let mut reader = csv::ReaderBuilder::new()
            .delimiter(b';')
            .from_path("questions.csv")?;

        let mut questions_diagram: Vec<Question> = Vec::new();

        for result in reader.deserialize() {
            let question: QuestionTup = result?;

            questions_diagram.push(Question {
                name: question.0,
                content: question.1,
                answer1: question.2,
                answer2: question.3,
                next1: question.4,
                next2: question.5,
                previous: question.6,
            });
        }

        Ok(questions_diagram)
    }

    pub fn print_question(&self) -> () {
        print!("{esc}c", esc = 27 as char);
        println!("=========================\nFuzzer Template Generator\n=========================");
        println!("{}\n", self.name);
        println!("{}\n", self.content);
        println!("\t{}\t{}\tUndo", self.answer1, self.answer2);
    }

    // Checks if the answer given by the user is one of the possibilities that the generator expects.
    pub fn validate_answer(&self, input: &mut String) -> bool {
        if input.ends_with("\r\n") {
            input.truncate(input.len() - 2);
        } else if input.ends_with("\n") {
            input.truncate(input.len() - 1);
        }

        // For now we dont check for variants (with the implementation of an interface this wont be necessary).
        // The "Undo" option makes the generator go back to the previous question, so if the user do something
        // by mistake, they can correct it.
        if (input == &self.answer1) || (input == &self.answer2) || (input == "Undo") {
            return true;
        }

        false
    }

    pub fn next_question(
        &self,
        q_diagram: &mut Vec<Question>,
        input: &String,
        q_index: usize,
    ) -> usize {
        // If it's equal to answer1, we go to next1, which is the next question if answer1 is chosen.
        if input == &self.answer1 {
            // We save the index of the current question in the 'previous' field of the next one.
            q_diagram[self.next1].previous = q_index;

            self.next1
        } else if input == &self.answer2 {
            q_diagram[self.next2].previous = q_index;

            self.next2
        }
        // Undo option.
        else {
            self.previous
        }
    }
}
