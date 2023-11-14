use graphviz_rust::{
    cmd::{CommandArg, Format},
    exec,
    printer::PrinterContext,
};
use serde::Deserialize;
use std::{
    fs::{create_dir, read_to_string, OpenOptions},
    io::Write,
    path::Path,
    process::Command,
};
use toml::from_str;

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

#[derive(Clone, Deserialize, PartialEq, Debug)]
pub struct Answer {
    pub was_chosen: bool, // Used when undoing
    pub answer: String,
    pub next: String,      // The next question if this answer is chosen.
    pub code: String,      // The code added to the file.
    pub skip: Vec<String>, // The questions to skip.
}

impl Question {
    // Builds the diagram of questions from the toml file.
    // The diagram is a vector of Questions (vector of nodes): each Question, depending on the answer, will have the index of the next
    // Question that should be asked.
    pub fn new() -> Vec<Question> {
        let contents = read_to_string("new.toml").expect("Failed to read questions file.");

        let q_list: QuestionList = from_str(&contents).expect("Failed to parse toml questions.");

        q_list.question
    }

    pub fn end(&self) -> bool {
        if self.id == "END" {
            return true;
        }

        false
    }

    pub fn print_question(&self) {
        let mut output = String::new();

        // Construct the output string
        output.push_str(&format!(
            "+=====================+\n|    libafl wizard    |\n+=====================+\n"
        ));
        output.push_str(&format!("{}\n\n", self.title));
        output.push_str(&format!("{}\n\n\t", self.content));

        for ans in &self.answers {
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
        
        for ans in &self.answers {
            if validate_input(&input, &ans.answer) {
                return true;
            }
        }

        if validate_input(&input, &String::from("Undo")) {
            return true;
        }

        false
    }

    pub fn chosen_ans(&self) -> usize {
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
                // // If this question has more than one answer, but all lead to the same next question.
                // if ans.next.len() == 1 {
                //     i = 0;
                // }

                let mut next_q = find_question(questions, &ans.next);

                // If the question should be skipped, then the generator goes to next question.
                // These types of questions should always have only one possibility for next question.
                while !questions[next_q].skipped_by.is_empty() {
                    next_q = find_question(questions, &ans.next);
                    //&self.next[0]
                }

                return (next_q, i);
            }
        }

        (0, 0)
    }

    pub fn skip_questions(&self, questions: &mut Vec<Question>, ans_i: usize) {
        for q_id in &self.answers[ans_i].skip {
            let i = questions
                .iter()
                .position(|question| &question.id == q_id)
                .unwrap();

            questions[i].skipped_by = self.id.clone();
        }
    }

    // Since we dont save which answer was chosen, we skip everything.
    pub fn unskip_questions(&self, questions: &mut Vec<Question>, ans_i: usize) {
        for q_id in &self.answers[ans_i].skip {
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

// Requires 'graphviz' to be installed on the machine, or results in an error.
pub fn flowchart_image(questions: &Vec<Question>) {
    let mut dot_string = String::from("digraph t {\n");

    for q in questions {
        if !q.end() {
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
                        "\t\"{}\" -> \"{}\"\n[label=\"{}...\"]",
                        q.title, questions[j].title, q.answers[0].answer,
                    ));
                }
            }
            // Multiple answers that lead to distinct next questions.
            else {
                for ans in &q.answers {
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

pub fn separate_code(code_content: Vec<String>) -> Vec<String> {
    // List of libafl's components
    let components = vec![
        "Observer",
        "Feedback",
        "State",
        "Monitor",
        "Event",
        "Scheduler",
        "Fuzzer",
        "Executor",
        "Generator",
        "Mutator",
        "Stage",
    ];

    let mut new_code_content: Vec<String> = Vec::new();
    let mut code_line = String::new();
    let mut pos = 0;

    // Each field of 'code_content' contains rust code but not necessarily individual declarations of components, so we separate
    // the instances of components.
    for code_string in code_content {
        while pos < code_string.len() {
            let mut found_index = None;

            // Iterate through the components to find the next occurrence.
            for component in &components {
                if let Some(index) = code_string[pos..].find(component) {
                    found_index = Some(pos + index);
                    break;
                }
            }

            match found_index {
                Some(index) => {
                    let mut end = index;
                    code_line.push_str(&code_string[pos..end]);

                    // We copy the declaration of the component until we hit a ';' (end of a statement).
                    for c in code_string[end..].chars() {
                        if c == ';' {
                            code_line.push(c);
                            end += 1;
                            break;
                        } else {
                            code_line.push(c);
                        }

                        end += 1;
                    }

                    // Now, 'code_string' contains everything up to (including) the declaration of the component.
                    new_code_content.push(code_line.clone());
                    code_line.clear();
                    pos = end;
                }
                None => {
                    // If it does not contain a component, we join it with the next component declaration.
                    code_line.push_str(&code_string[pos..]);
                    break;
                }
            }
        }
    }

    new_code_content
}

pub fn arrange_code(code_content: Vec<String>) -> Vec<String> {
    // List of libafl's components
    let components = vec![
        "Observer",
        "Feedback",
        "State",
        "Monitor",
        "Event",
        "Scheduler",
        "Fuzzer",
        "Executor",
        "Generator",
        "Mutator",
        "Stage",
    ];

    let mut new_code_content: Vec<String> = Vec::new();

    for code_string in code_content {
        if new_code_content.is_empty() {
            new_code_content.push(code_string);
        } else {
            let mut insert_index = 0;
            let mut inserted = false;

            for (i, s) in new_code_content.iter().enumerate() {
                for comp in &components {
                    // Checks if the string we want to insert contains a component that should come before the current one.
                    if code_string.contains(comp) && !s.contains(comp) {
                        insert_index = i;
                        inserted = true;
                        break;
                    }
                }

                if inserted {
                    break;
                }
            }

            if !inserted {
                new_code_content.push(code_string);
            } else {
                new_code_content.insert(insert_index, code_string);
            }
        }
    }

    new_code_content
}

// Write Rust code in the file of the generated fuzzer.
pub fn write_code(code_content: Vec<String>) -> String {
    let mut counter = 0;
    let mut file_name = format!("fuzzer.rs");

    let fuzzers_folder = "./fuzzers";
    if !Path::new(fuzzers_folder).exists() {
        create_dir(fuzzers_folder).expect("Failed to create fuzzers directory.");
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
    let input_low = input.to_lowercase();
    let mut input_chars = input_low.chars();
    let ans_low = ans.to_lowercase();
    let mut ans_chars = ans_low.chars();

    // Basically, an aswer is valid if it is an acceptable variant of that given answer. Acceptable variants are strings that contain
    // the characters in the same order as the answer, so for the answer "Yes", acceptable variants are: "y", "Ye", "yes", "YES", but
    // not "Yess", "yy", "Yhes", "yYess"...
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

// Resolves the index in the vector for the specific question.
pub fn find_question(questions: &Vec<Question>, q: &String) -> usize {
    questions
        .iter()
        .position(|question| &question.id == q)
        .unwrap()
}
