use serde::Deserialize;
use std::{fs, fs::OpenOptions, io::Write, path::Path, process::Command};
use toml;

#[derive(Deserialize)]
struct Sections {
    in_process_skip_questions: Vec<String>,
    forkserver_skip_questions: Vec<String>,
}

// Used to read the TOML file
#[derive(Deserialize)]
struct QuestionList {
    question: Vec<Question>,
}

#[derive(Clone, Deserialize, PartialEq, Debug)]
pub struct Question {
    id: String, // ID is resolved to local indexes.
    pub title: String,
    pub content: String, // Description related to the question, to help the user.
    pub answers: Vec<String>, // A vector containing all the possible answers for this question.
    next: Vec<String>, // A vector containing the next question for all the possible answers (for answer[0] the next question is next[0]...).
    code: Vec<String>, // Contains the Rust code associated to the question.
    previous: usize,   // The question that led to the current one.
    skip: bool,        // Marks questions that should be skipped.
}

impl Question {
    // Builds the diagram of questions from the csv file (this will probably be changed, the csv is used only for demonstrative purposes).
    // The diagram is a vector of Questions (vector of nodes): each Question, depending on the answer, will have the index of the next Question
    // that should be asked.
    pub fn new() -> Vec<Question> {
        let contents =
            fs::read_to_string("questions.toml").expect("Failed to read questions file.");

        let q_list: QuestionList =
            toml::from_str(&contents).expect("Failed to parse toml questions.");

        // // Checks if each question is valid.
        // for q in q_list.question.iter() {
        //     q.validate_question()?;
        // }

        q_list.question
    }

    pub fn end(&self) -> bool {
        if self.id == "end" {
            return true;
        }

        false
    }

    pub fn print_question(&self) {
        let mut output = String::new();

        clear_terminal_screen();

        // Construct the output string
        output.push_str(&format!(
            "=========================\nFuzzer Template Generator\n=========================\n"
        ));
        output.push_str(&format!("{}\n\n", self.title));
        output.push_str(&format!("{}\n\n", self.content));

        for ans in &self.answers {
            output.push_str(&format!("\t{}", ans));
        }

        output.push_str("\tUndo\n");

        print!("{}", output);
    }

    pub fn resolve_answer(
        &self,
        questions: &Vec<Question>,
        input: &String,
    ) -> (usize, bool, usize) {
        // The "Undo" option makes the generator go back to the previous question, so if the user do something by mistake, they can correct it.
        if validate_input(&input, &String::from("Undo")) {
            return (self.previous, true, 0);
        }

        // Checks if the user typed one of the acceptable answers. If so, returns the index of the next question associated to that answer.
        // For now we don't check for variants.
        for (i, ans) in self.answers.iter().enumerate() {
            if validate_input(&input, &ans) {
                let mut next_q = self.next_question(questions, i);

                // If the question should be skipped, then the generator goes to next question.
                // These types of questions should always have only one possibility for next question (this is the approach for now).
                while questions[next_q].skip {
                    next_q = questions[next_q].next_question(questions, 0);
                }

                return (next_q, true, i);
            }
        }

        (0, false, 0)
    }

    // Resolves the index in the vector for the next question
    pub fn next_question(&self, questions: &Vec<Question>, i: usize) -> usize {
        questions
            .iter()
            .position(|question| question.id == self.next[i])
            .unwrap()
    }

    pub fn has_code(&self) -> bool {
        if !self.code.is_empty() {
            return true;
        }

        false
    }

    pub fn has_title(&self) -> bool {
        if !self.title.is_empty() {
            return true;
        }

        false
    }

    pub fn add_code(&self, code_content: &mut Vec<String>, ans_i: usize) {
        if self.code[ans_i] != "" {
            code_content.push(self.code[ans_i].to_string());
        }
    }

    pub fn check_skip(
        &self,
        questions: &mut Vec<Question>,
        input: &String,
        next_q: usize,
        in_process_qs: &Vec<String>,
        forkserver_qs: &Vec<String>,
    ) {
        // If the user doesn't have the source code or can't provide a harness, then in process fuzzing in not possible and the questions
        // related to it are skipped.
        if ((self.id == "source code") || (self.id == "harness"))
            && validate_input(&input, &String::from("No"))
        {
            skip_questions(questions, &in_process_qs);
        }
        // If it is possible, then forkserver/llmp questions are skipped.
        else if (self.id == "harness") && validate_input(&input, &String::from("Yes")) {
            skip_questions(questions, &forkserver_qs);
        // If the user is undoing, then the generator resets the questions that were marked to be skipped.
        } else if ((self.id == "harness")
            || (self.id == "observers")
            || (self.id == "map size"
                && (questions[next_q].id == "source code" || questions[next_q].id == "harness")))
            && validate_input(&input, &String::from("Undo"))
        {
            unskip_questions(questions, &in_process_qs);
            unskip_questions(questions, &forkserver_qs);
        }
    }

    pub fn update_previous(&mut self, curr_q: usize) -> () {
        // Saves the current questions as the previous for the next one.
        self.previous = curr_q;
    }
}

pub fn read_sections() -> (Vec<String>, Vec<String>) {
    let contents = fs::read_to_string("sections.toml").expect("Failed to read sections file.");

    let sections: Sections = toml::from_str(&contents).expect("Failed to parse toml sections.");

    (
        sections.in_process_skip_questions,
        sections.forkserver_skip_questions,
    )
}

pub fn skip_questions(questions: &mut Vec<Question>, vec: &Vec<String>) -> () {
    for q in vec {
        let i = questions
            .iter()
            .position(|question| &question.id == q)
            .unwrap();

        questions[i].skip = true;
    }
}

// Undo option
pub fn unskip_questions(questions: &mut Vec<Question>, vec: &Vec<String>) -> () {
    for q in vec {
        let i = questions
            .iter()
            .position(|question| &question.id == q)
            .unwrap();

        questions[i].skip = false;
    }
}

pub fn replace_code(code_content: &mut Vec<String>) -> () {
    let mut symb_count: usize;

    // For each String of Rust code that contains a '$', we replace this '$' by another String (another Rust code). This works like in wrappers.
    // The only requirement is that, for each '$' found in that String, the order of replacement is: the firt occurence is replaced by
    // the code that is at 'position_of_string - number_of_occ_of_$'. Then, since this String will be removed from the vector, the next occ of '$'
    // can be replaced by a String at the same position (i - symb_count).
    for s in code_content.clone() {
        if s.contains('$') {
            // Current position
            let i = code_content
                .iter()
                .position(|code| code.as_str() == s)
                .unwrap();

            symb_count = s.chars().filter(|&c| c == '$').count();

            for c in s.chars() {
                if c == '$' {
                    // Since this component will be wrapped by another, it doesn't need to have an assigment to a variable.
                    //"let observer = StdMapObserver::new()" will become "StdMapObserver::new()"
                    if let Some(index) = code_content[i - symb_count].find("= ") {
                        code_content[i - symb_count].replace_range(..=index + 1, "");
                    }

                    code_content[i] = s.replacen('$', &code_content[i - symb_count], 1);

                    code_content.remove(i - symb_count);
                }
            }
        }
    }
}

// pub fn arrange_code(code_content: Vec<String>) -> Vec<String> {
//     // List of libafl's components
//     let components: Vec<String> = vec!["Observer", "Feedback", "State", "Monitor", "Event", "Scheduler", "Fuzzer", "Executor", "Generator", "Mutator", "Stage"];

//     let code_line = String::new();

//     let mut final_code: Vec<String> = Vec::new();

//     // Each of the fields of 'code_content' contains a String, which contains a single or mroe lines of Rust code.
//     // The idea here is to parse each String, looking for the Strings contained in 'components' as a substring, to find the components that
//     // are going to be used.
//     for s in code_content {
//         for c in s.chars() {
//             if c == ';' {
//                 code_line.push(c);

//                 // 'code_line' contains a line of Rust code, so we check to see if it's a component.
//                 if let Some((i, _)) = components.iter().enumerate().find(|(_, comp)| code_line.contains(comp)) {
//                     // If it's a component, we must write it to 'final_code' in the same order as the 'components' vector.
//                     for (j, code) in final_code.iter().enumerate() {
//                         if let Some(k) = components.iter().position(|&other_comp| code.contains(other_comp)) {
//                             // If the current component in 'final_code' contains the same class of component, or if it contains a class that
//                             // goes after the current one, we place it in this position.
//                             if (other_comp == comp) || (i < k) {
//                                 final_code.insert(j, code_line);
//                                 break;
//                             }
//                         }

//                         // If we've gone through the whole 'final_code' vector and didn't insert the code, this means we have a component
//                         // that must be add to the end.
//                         if j == final_code.len() {
//                             final_code.push(code_line);
//                             break;
//                         }
//                     }
//                 }
//                 else {
//                     // If it's not a component, we simply add it to the end.
//                     final_code.push(code_line);
//                 }
//             }
//             else {
//                 code_line.push(c);
//             }
//         }
//     }

//     final_code
// }

// Write Rust code in the file of the generated fuzzer.
pub fn write_code(code_content: Vec<String>) -> String {
    let mut counter = 0;
    let mut file_name = format!("fuzzer.rs");

    let fuzzers_folder = "./fuzzers";
    if !Path::new(fuzzers_folder).exists() {
        fs::create_dir(fuzzers_folder).expect("Failed to create fuzzers directory.");
    }

    // Creates "fuzzer.rs", "fuzzer_1.rs" files if the previous one already exists...
    while Path::new(&format!("{}/{}", fuzzers_folder, file_name)).exists() {
        counter += 1;
        file_name = format!("fuzzer_{}.rs", counter);
    }

    let file_path = format!("{}/{}", fuzzers_folder, file_name);

    let mut out_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&file_path)
        .expect("Failed to open the fuzzer file.");

    // While imports are not resolved, use this.
    out_file
        .write_all("use libafl::prelude::*;\n\n".as_bytes())
        .expect("Failed to write to the fuzzer file.");

    for (i, code) in code_content.iter().enumerate() {
        out_file
            .write_all(code.as_bytes())
            .expect("Failed to write to the fuzzer file.");

        if i < code_content.len() {
            out_file
                .write_all(";\n\n".as_bytes())
                .expect("Failed to write to the fuzzer file.");
        }
    }

    file_name
}

pub fn validate_input(input: &String, ans: &String) -> bool {
    let input_lower = input.to_lowercase();
    let ans_lower = ans.to_lowercase();

    let mut input_chars = input_lower.chars();
    let mut ans_chars = ans_lower.chars();

    // Basically, an aswer is valid if it is an acceptable variant of that given answer. Acceptable variants are strings that contain the
    // characters in the same order as the answer, so for the answer "Yes", acceptable variants are: "y", "Ye", "yes", "YES", but not
    // "Yess", "yy", "Yhes", "yYess"...
    while let (Some(input_c), Some(ans_c)) = (input_chars.next(), ans_chars.next()) {
        if input_c != ans_c {
            return false;
        }
    }

    true
}

pub fn clear_terminal_screen() {
    if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(["/c", "cls"])
            .spawn()
            .expect("cls command failed to start")
            .wait()
            .expect("failed to wait");
    } else {
        Command::new("clear")
            .spawn()
            .expect("clear command failed to start")
            .wait()
            .expect("failed to wait");
    };
}
