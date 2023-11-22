use std::{
    fs::{create_dir, OpenOptions},
    io::Write,
    path::Path,
    process::Command,
};

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

pub fn separate_code(code_content: Vec<String>) -> Vec<String> {
    // List of libafl's components.
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

    let mut separated_code: Vec<String> = Vec::new();

    for code_string in code_content {
        let mut current_line = String::new();
        let mut in_code_block = false;

        for c in code_string.chars() {
            current_line.push(c);

            if !in_code_block {
                if components.iter().any(|&s| current_line.contains(s)) {
                    in_code_block = true;
                }
            }

            if in_code_block && c == ';' {
                in_code_block = false;
                separated_code.push(current_line.trim().to_string());
                current_line.clear();
            }
        }

        separated_code.push(current_line.trim().to_string());
    }

    separated_code
}

pub fn arrange_code(code_content: Vec<String>) -> Vec<String> {
    // List of libafl's components.
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

    let mut ordered_code_content: Vec<String> = Vec::new();
    let mut unmatched_lines: Vec<String> = Vec::new();

    for code_line in code_content.iter() {
        let mut matched = false;

        for component in components.iter() {
            if code_line.contains(component) {
                ordered_code_content.push(code_line.to_string());
                matched = true;
                break;
            }
        }

        if !matched {
            unmatched_lines.push(code_line.to_string());
        }
    }

    // Append unmatched lines at the end.
    ordered_code_content.extend(unmatched_lines);

    ordered_code_content
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
        .write_all("use libafl::prelude::*;\n\nfn main() {".as_bytes())
        .expect("Failed to write to the fuzzer file.");

    for (i, code) in code_content.iter().enumerate() {
        out_file
            .write_all("\n".as_bytes())
            .expect("Failed to write to the fuzzer file.");

        out_file
            .write_all(code.as_bytes())
            .expect("Failed to write to the fuzzer file.");

        if i < code_content.len() {
            out_file
                .write_all("\n\n".as_bytes())
                .expect("Failed to write to the fuzzer file.");
        }
    }

    out_file
        .write_all("}".as_bytes())
        .expect("Failed to write to the fuzzer file.");

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
