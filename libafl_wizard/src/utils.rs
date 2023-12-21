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

            // The end of the declaration of a component.
            if in_code_block && c == ';' {
                in_code_block = false;
                separated_code.push(current_line.trim().to_string());
                current_line.clear();
            }
        }

        if !current_line.trim().to_string().is_empty() {
            separated_code.push(current_line.trim().to_string());
        }
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

    let mut ordered_code: Vec<String> = Vec::new();
    let mut placed_code: Vec<bool> = vec![false; code_content.len()];

    for comp in components {
        for (i, code_line) in code_content.iter().enumerate() {
            if code_line.contains(comp) {
                // Place in the correct order.
                ordered_code.push(code_line.to_string());
                placed_code[i] = true;
            }
        }
    }

    // Deals with cases where there is no definition of a component.
    for (i, code_line) in code_content.iter().enumerate() {
        if !placed_code[i] {
            ordered_code.insert(i, code_line.to_string());
        }
    }

    ordered_code
}

pub fn write_code(code_content: Vec<String>, imports: Vec<String>) -> String {
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

    for i in imports {
        out_file
            .write_all(&format!("{}\n", i).as_bytes())
            .expect("Failed to write to the fuzzer file.");
    }

    out_file
        .write_all(&format!("\nfn main() {}", "{\n").as_bytes())
        .expect("Failed to write to the fuzzer file.");

    for code in code_content.iter() {
        out_file
            .write_all(&format!("{}{}\n\n", " ".repeat(4), code).as_bytes())
            .expect("Failed to write to the fuzzer file.");
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

pub fn separate_imports(code_content: Vec<String>) -> (Vec<String>, Vec<String>) {
    let mut imports: Vec<String> = Vec::new();
    let mut new_code_content: Vec<String> = Vec::new();

    for code in code_content.iter() {
        let mut is_import = false;
        let mut import_string = String::new();
        let mut code_string = String::new();

        for line in code.lines() {
            if is_import {
                import_string.push_str(&format!("{}\n", line));
                if line.contains(";") {
                    is_import = false;
                    imports.push(import_string.trim_end().to_string());
                    import_string.clear();
                }
            } else {
                let trimmed_line = line.trim();
                if trimmed_line.starts_with("use") {
                    if !line.contains(";") {
                        is_import = true;
                        import_string.push_str(&format!("{}\n", line));
                    } else {
                        imports.push(format!("{}\n", line).trim_end().to_string());
                    }
                } else {
                    if !trimmed_line.is_empty() {
                        code_string.push_str(&format!("{}\n", line));
                    } else {
                        code_string.push_str("\n");
                    }
                }
            }
        }
        new_code_content.push(code_string.trim_end().to_string());
    }

    (imports, new_code_content)
}

pub fn arrange_imports(imports_content: Vec<String>) -> Vec<String> {
    // Each field of 'result' is a single import (use).
    let mut result: Vec<String> = Vec::new();

    for import in imports_content {
        let mut i: Option<usize> = None;
        let mut single_line_import = false;

        // Check if the crate that we are trying to insert is already in the 'result' vector (final imports).
        if let Some(i_line) = import.lines().next() {
            if let Some(crate_name) = parse_imports(i_line.trim().to_string()).iter().next() {
                println!("CRATE NAME: {}", crate_name);
                single_line_import = crate_name.contains(";");
                if let Some(index) = result
                    .iter()
                    .position(|s| s.starts_with(&format!("use {}", crate_name)))
                {
                    i = Some(index)
                }
            }
        }

        match i {
            Some(i) => {
                let mut single_line_result = false;

                if let Some(r_line) = result[i].lines().next() {
                    if let Some(crate_name) = parse_imports(r_line.trim().to_string()).iter().next() {
                        single_line_result = crate_name.contains(";");
                    }
                }
                if single_line_import {
                    let import_names = parse_imports(import.trim().to_string());

                    if single_line_result {
                        // Both are single line imports, so no need to iterate through their "lines".
                        let result_names = parse_imports(result[i].trim().to_string());

                        if let Some(new_import) = insert_import(&import_names, &result_names, &result[i]) {
                            result[i] = new_import;
                        }
                    } else {
                        // Single line into multiline.
                        let mut r_lines_iter = result[i].lines();

                        while let Some(r_line) = r_lines_iter.next() {
                            let result_names = parse_imports(r_line.trim().to_string());

                            if let Some(new_import) = insert_import(&import_names, &result_names, &result[i]) {
                                result[i] = new_import;
                                break;
                            }
                        }
                    }
                } else {
                    let mut i_lines_iter = import.lines();

                    if single_line_result {
                        // Multiline into single, so we simply do the opposite.
                        let result_names = parse_imports(result[i].trim().to_string());

                        while let Some(i_line) = i_lines_iter.next() {
                            let i_line_names = parse_imports(i_line.trim().to_string());

                            if let Some(new_import) = insert_import(&result_names, &i_line_names, &result[i]) {
                                result[i] = new_import;
                                break;
                            }
                        }
                    } else {
                        // Both are multiline imports, so we have to iterate through their lines until the last component is checked for insertion.
                        let mut r_lines_iter = result[i].lines();
                        let mut temp_import = String::new();

                        while let Some(r_line) = r_lines_iter.next() {
                            if let Some(i_line) = import.lines().next() {
                                let r_line_names = parse_imports(r_line.trim().to_string());
                                let i_line_names = parse_imports(i_line.trim().to_string());

                                if let Some(new_import) = insert_import(&i_line_names, &r_line_names, &result[i])
                                {
                                    temp_import = new_import;
                                }
                            }
                        }
                        result[i] = temp_import
                    }
                }
            }
            None => {
                // Insert and sort alphabetically.
                result.push(import.trim().to_string());
                result.sort();
            }
        }
    }

    println!("\nRESULT:");
    for i in &result {
        println!("{}", i);
    }
    result
}

fn parse_imports(import: String) -> Vec<String> {
    let mut imports_names: Vec<String> = Vec::new();

    if let Some(import_stripped) = import.trim().strip_prefix("use ") {
        let mut import_string = String::new();
        let mut chars = import_stripped.chars().peekable();

        while let Some(c) = chars.next() {
            import_string.push(c);

            // We want to break the import string into 'word::', 'word};'... patterns.
            if c == ':' || c == '{' || c == '}' || c == ',' || c == ';' {
                if import_string.contains("::") {
                    if let Some(&next_char) = chars.peek() {
                        if next_char != '{' {
                            imports_names.push(import_string.trim().to_string().clone());
                            import_string.clear();
                        }
                    }
                } else if import_string.contains(",") || import_string.contains(";") {
                    imports_names.push(import_string.trim().to_string().clone());
                    import_string.clear();
                }
            }
        }
    }

    // Resolve "};" characters
    let mut indices_to_remove: Vec<usize> = Vec::new();

    for (index, string) in imports_names.iter().enumerate() {
        if string.contains("};") {
            indices_to_remove.push(index);
        }
    }

    for index in indices_to_remove.iter().rev() {
        let string = imports_names[*index].clone();

        imports_names[index - 1] += &string;
        imports_names.remove(*index);
    }

    imports_names
}

fn rm_punct(input: &String) -> String {
    // Removes the ';', '::', etc from the string.
    input
        .chars()
        .filter(|&c| c != ':' && c != ';' && c != ',' && c != '{' && c != '}')
        .collect()
}

fn insert_import(import: &Vec<String>, result: &Vec<String>, curr_import: &String) -> Option<String> {
    // Basically, we try to insert 'import' in 'result', as a new string.
    let mut new_import = curr_import.clone();
    let mut i_iter = import.iter();
    let mut r_iter = result.iter();

    if let Some(i_name_punct) = i_iter.next() {
        if let Some(r_name_punct) = r_iter.next() {
            let i_name = rm_punct(&i_name_punct);
            let r_name = rm_punct(&r_name_punct);

            if i_name == r_name {
                // Insert into this module.
                while let Some(r_name_punct) = r_iter.next() {
                    if let Some(i_name_punct) = i_iter.next() {
                        let r_name = rm_punct(&r_name);

                        if i_name < r_name {
                            if let Some(position) = new_import.find(r_name_punct) {
                                let mut insert_string = String::new();
                                insert_string.push_str(i_name_punct);

                                while let Some(i_name_punct) = i_iter.next() {
                                    insert_string.push_str(i_name_punct);
                                }
                                insert_string = insert_string.replace(";", ",");

                                new_import.insert_str(position, &insert_string);

                                return Some(new_import);
                            }
                        } else if r_name_punct.contains("},") && i_name > r_name {
                            if let Some(position) = new_import.find(r_name_punct) {
                                let mut insert_string = String::new();
                                insert_string.push_str(i_name_punct);

                                while let Some(i_name_punct) = i_iter.next() {
                                    insert_string.push_str(i_name_punct);
                                }
                                insert_string = insert_string.replace(";", "},");
                                new_import = new_import.replace("},", ",");
                                new_import.insert_str(position, &insert_string);

                                return Some(new_import);
                            }
                        }
                    }
                }
            } else if i_name < r_name {
                // No equal module was found, so insert here.
                if let Some(position) = new_import.find(r_name_punct) {
                    let mut insert_string = String::new();
                    insert_string.push_str(i_name_punct);

                    while let Some(i_name_punct) = i_iter.next() {
                        insert_string.push_str(i_name_punct);
                    }
                    insert_string = insert_string.replace(";", ",");
                    insert_string.push_str("\n");
                    new_import.insert_str(position, &insert_string);

                    return Some(new_import);
                }
            } else {
                if r_name_punct.contains("};") && (i_name > r_name) {
                    // Insert it as the last import.
                    if let Some(position) = new_import.find(r_name_punct) {
                        let mut insert_string = String::new();
                        insert_string.push_str(i_name_punct);

                        while let Some(i_name_punct) = i_iter.next() {
                            insert_string.push_str(i_name_punct);
                        }
                        insert_string = insert_string.replace(";", "};");
                        new_import = new_import.replace("};", ",");
                        new_import.insert_str(position, &insert_string);

                        return Some(new_import);
                    }
                }
            }
        }
    }

    None
}
