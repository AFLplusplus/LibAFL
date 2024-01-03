use std::{
    fs::{create_dir, OpenOptions},
    io::Write,
    path::Path,
    process::Command,
};

/// Clears the terminal screen.
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

/// Returns true if the 'input' provided by the user is equal to 'ans'.
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

/// Returns a vector containing indivdual declarations of Libafl's components
/// and sorted according to correct order of components.
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

    let code_content = separate_code(code_content, &components);

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

/// Returns a vector containing individual declarations of Libafl's components.
fn separate_code(code_content: Vec<String>, components: &Vec<&str>) -> Vec<String> {
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

/// Creates a file and writes the imports and code to that file.
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

/// Returns a tuple containing a vector with only the code of the components and
/// another containing only the imports.
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
                    imports.push(format_import(&import_string));
                    import_string.clear();
                }
            } else {
                let trimmed_line = line.trim();
                if trimmed_line.starts_with("use") {
                    if !line.contains(";") {
                        is_import = true;
                        import_string.push_str(&format!("{}\n", line));
                    } else {
                        imports.push(format_import(&line.to_string()));
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

/// Fixes identation and new line characters for the imports.
fn format_import(import: &String) -> String {
    let mut new_import = String::new();

    for (index, line) in import.lines().enumerate() {
        let mut line = line.trim().to_string();

        if index > 0 {
            if line != "};" {
                line.insert_str(0, "    ");
                line.push('\n');
                new_import.push_str(&line);
            } else {
                new_import.push_str(&line);
            }
        } else {
            if !line.contains(";") {
                line.push('\n');
            }
            new_import.push_str(&line);
        }
    }

    new_import
}

/// Arranges all the imports by sorting them alphabetically and making
/// insertions.
///
/// For example, if there are two 'use libafl::' imports, then their code
/// will be joined so that it becomes only one 'use libafl::' import.
pub fn arrange_imports(imports_content: Vec<String>) -> Vec<String> {
    // Each field of 'result' will be a single import/use of a crate, after the insertions.
    let mut result: Vec<String> = Vec::new();

    for import in imports_content {
        let mut i: Option<usize> = None;

        // Check if the crate that we are trying to insert is already in 'result'.
        if let Some(i_line) = import.lines().next() {
            if let Some(crate_name) = i_line.split("::").next() {
                if let Some(index) = result.iter().position(|s| s.starts_with(crate_name)) {
                    i = Some(index);
                }
            }
        }

        match i {
            Some(i) => {
                let mut i_lines = import.lines();
                let mut r_lines = result[i].lines().peekable();

                while let Some(i_line) = i_lines.next() {
                    if i_line != "};" {
                        let mut i_chars = i_line.chars().peekable();
                        let mut i_name_punct = next_module_name(&i_chars);

                        if i_name_punct.starts_with("use ") {
                            i_name_punct = next_module_name(&i_chars);
                        }
                        let i_name = rm_punct(&i_name_punct).trim();

                        while let Some(r_line) = r_lines.next() {
                            if r_line != "};" {
                                let mut r_chars = r_line.chars().peekable();
                                let mut r_name_punct = next_module_name(&r_chars);

                                if r_name_punct.starts_with("use ") {
                                    r_name_punct = next_module_name(&r_chars);
                                }
                                let r_name = rm_punct(&r_name_punct).trim();

                                if i_name == r_name {
                                    // Iterate on this line.
                                    loop {
                                        i_name_punct = next_module_name(&i_chars); 
                                        i_name = rm_punct(&i_name_punct).trim();
                                        r_name_punct = next_module_name(&r_chars);
                                        r_name = rm_punct(&r_name_punct).trim();

                                        if i_name < r_name {
                                            // Check if have to make it a multiple import here.
                                        } else if i_name > r_name {
                                            if let None = peek_next_module_name(&r_chars) {
                                                // Insert at the end and check if have to make it a multiple import.
                                            }
                                        }
                                    }
                                } else if i_name < r_name {
                                    if r_line.ends_with(";") {
                                        // If inserting in a SL: then make it ML and insert at the beginning.
                                        let (first, second) = r_line.split_inclusive("::");
                                        let insert_line = i_line.trim().to_string();

                                        first.push_str("{\n");
                                        if insert_line.starts_with("use ") {
                                            insert_line =
                                                insert_line.split_once("::").skip(1).collect();
                                        }
                                        insert_line.insert_str(0, &" ".repeat(4));
                                        insert_line.push('\n');
                                        insert_line = insert_line.replace(";", ",");
                                        second.insert_str(0, &" ".repeat(4));
                                        second.push('\n');
                                        second = second.replace(";", ",");
                                        result[i] =
                                            format!("{}{}{}{}", first, insert_line, second, "};");
                                    } else {
                                        // If inserting in ML, simply insert the line here.
                                        let mut result_lines = result[i].lines().collect();

                                        for (i, line) in result[i].lines().enumerate() {
                                            if line.contains(r_name_punct) {
                                                let insert_line = i_line.trim().to_string();

                                                if insert_line.starts_with("use ") {
                                                    insert_line = insert_line
                                                        .split_once("::")
                                                        .skip(1)
                                                        .collect();
                                                }
                                                insert_line.insert_str(0, &" ".repeat(4));
                                                insert_line.push('\n');
                                                insert_line = insert_line.replace(";", ",");
                                                result_lines.insert(i, insert_line);
                                                break;
                                            }
                                        }
                                        result[i] = result_lines.join("");
                                        break;
                                    }
                                } else {
                                    if r_line.ends_with(";") {
                                        // If inserting in a SL: the make it ML and insert the line at the end.
                                        let (first, second) = r_line.split_inclusive("::");
                                        let insert_line = i_line.trim().to_string();

                                        first.push_str("{\n");
                                        second.insert_str(0, &" ".repeat(4));
                                        second.push('\n');
                                        second = second.replace(";", ",");
                                        if insert_line.starts_with("use ") {
                                            insert_line =
                                                insert_line.split_once("::").skip(1).collect();
                                        }
                                        insert_line.insert_str(0, &" ".repeat(4));
                                        insert_line.push('\n');
                                        insert_line = insert_line.replace(";", ",");
                                        result[i] =
                                            format!("{}{}{}{}", first, second, insert_line, "};");
                                        break;
                                    } else {
                                        // If inserting in ML, if there arent anymore lines: then insert the line at the end.
                                        if let Some(end) = r_lines.peek() {
                                            if end == "};" {
                                                let mut result_lines = result[i].lines().collect();
                                                let insert_line = i_line.trim().to_string();

                                                if insert_line.starts_with("use ") {
                                                    insert_line = insert_line
                                                        .split_once("::")
                                                        .skip(1)
                                                        .collect();
                                                }
                                                insert_line.insert_str(0, &" ".repeat(4));
                                                insert_line.push('\n');
                                                insert_line = insert_line.replace(";", ",");
                                                result_lines
                                                    .insert(result_lines.len() - 2, insert_line);
                                                result[i] = result_lines.join("");
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
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

    result
}

/// Returns the next module name for an iterator of characters of a line of an
/// import.
fn next_module_name<I>(chars: &mut std::iterator::Peekable<I>) -> String
where
    I: Iterator<Item = char>,
{
    let mut module_name = String::new();

    while let Some(c) = chars.next() {
        module_name.push(c);

        if c == ':' {
            if module_name.contains("::") {
                if let Some(&next_char) = chars.peek() {
                    if next_char != '{' {
                        break;
                    }
                }
            }
        } else if module_name.contains(",") || module_name.contains("{") {
            if let Some(&next_char) = chars.peek() {
                if next_char != '\n' {
                    break;
                }
            }
        } else if c == ';' {
            break;
        }
    }

    module_name
}

/// Removes the punctuation characters of the name of a module.
fn rm_punct(input: &String) -> String {
    // Removes the ';', '::', etc from the string.
    input
        .chars()
        .filter(|&c| c != ':' && c != ';' && c != ',' && c != '{' && c != '}')
        .collect()
}
