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

    // Basically, an answer is valid if it is an acceptable variant of that given answer. Acceptable variants are strings that contain
    // the characters in the same order as the answer, so for the answer "Yes", acceptable variants are: "y", "Ye", "yes", "YES", but
    // not "Yess", "yy", "Yhes", "yYess"...
    while let Some(input_c) = input_chars.next() {
        if let Some(ans_c) = ans_chars.next() {
            if input_c != ans_c {
                return false;
            }
        } else {
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
/// For example, if there are two 'use libafl::' imports their code
/// will be joined, so that it becomes only one 'use libafl::' import.
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

                while let Some(i_line) = i_lines.next() {
                    if (i_line.starts_with("use ") && i_line.ends_with(";"))
                        || (!i_line.starts_with("use ") && i_line != "};")
                    {
                        let mut r_lines = result[i].lines().peekable();

                        while let Some(r_line) = r_lines.next() {
                            if (r_line.starts_with("use ") && r_line.ends_with(";"))
                                || (!r_line.starts_with("use ") && r_line != "};")
                            {
                                if let Some(new_result) =
                                    insert_import(i_line, r_line, r_lines.clone(), &result[i])
                                {
                                    result[i] = new_result;
                                    break;
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

/// Returns a vector containing all the modules names in a line of an import.
fn modules_names(line: &str) -> Vec<String> {
    let mut chars = line.chars().peekable();
    let mut module_name = String::new();
    let mut names: Vec<String> = Vec::new();

    while let Some(c) = chars.next() {
        module_name.push(c);

        if c == ':' {
            if module_name.contains("::") {
                if let Some(&next_char) = chars.peek() {
                    if next_char != '{' {
                        names.push(module_name.clone());
                        module_name.clear();
                    }
                }
            }
        } else if module_name.contains(",") || module_name.contains("{") {
            names.push(module_name.clone());
            module_name.clear();
        } else if c == ';' {
            names.push(module_name.clone());
            module_name.clear();
        }
    }

    names
}

/// Removes the punctuation characters from the end of the name of a module.
fn rm_punct(name: &String) -> String {
    let chars_to_remove = [';', ':', ',', '{', '}'];

    name.trim_end_matches(|c| chars_to_remove.contains(&c))
        .to_string()
}

/// Checks which kind of insertion should be applied to the import, based on the
/// name of the module.
fn insert_import<'a, T>(
    i_line: &str,
    r_line: &str,
    r_lines: std::iter::Peekable<T>,
    curr_result: &String,
) -> Option<String>
where
    T: Iterator<Item = &'a str>,
{
    let i_line_names = modules_names(i_line);
    let mut i_line_names_iter = i_line_names.iter().peekable();
    let mut i_name_punct = i_line_names_iter.next().unwrap().to_string();
    if i_name_punct.starts_with("use ") {
        i_name_punct = i_line_names_iter.next().unwrap().to_string();
    }
    let i_name = rm_punct(&i_name_punct);
    let i_name = i_name.trim().to_string();

    let r_line_names = modules_names(r_line);
    let mut r_line_names_iter = r_line_names.iter().peekable();
    let mut r_name_punct = r_line_names_iter.next().unwrap().to_string();
    if r_name_punct.starts_with("use ") {
        r_name_punct = r_line_names_iter.next().unwrap().to_string();
    }
    let r_name = rm_punct(&r_name_punct);
    let r_name = r_name.trim().to_string();

    if i_name == r_name {
        insert_on_line(i_line_names_iter, r_line_names_iter, r_line, curr_result)
    } else if i_name < r_name {
        insert_before_line(i_line, r_line, r_name_punct, curr_result)
    } else {
        insert_after_line(i_line, r_line, r_lines, curr_result)
    }
}

/// Inserts the import on the current line.
///
/// For example, "use libafl::feedback::CrashFeedback;" and
/// "use libafl::feedback::TimeoutFeedback" will return:
/// "use libafl::feedback::{CrashFeedback, TimeoutFeedback};"
fn insert_on_line<'a, T>(
    mut i_line_names_iter: std::iter::Peekable<T>,
    mut r_line_names_iter: std::iter::Peekable<T>,
    r_line: &str,
    curr_result: &String,
) -> Option<String>
where
    T: Iterator<Item = &'a String> + std::iter::DoubleEndedIterator,
    T: Clone,
{
    let mut inserted = false;
    let mut new_r_line = r_line.to_string();

    while let Some(i_name_punct) = i_line_names_iter.peek() {
        let i_name = rm_punct(&i_name_punct);

        if let Some(r_name_punct) = r_line_names_iter.peek() {
            let r_name = rm_punct(&r_name_punct);

            if i_name < r_name {
                if r_name_punct.ends_with(",") {
                    // Make it a multiple import and insert here.
                    let insert_string = rm_punct(&i_name_punct);
                    let (first, second) =
                        new_r_line.split_at(new_r_line.find(r_name_punct.as_str()).unwrap());
                    let second = rm_punct(&second.to_string());
                    let mut end = "},";

                    if new_r_line.ends_with(";") {
                        end = "};";
                    }
                    new_r_line = format!("{}{}{}, {}{}", first, "{", insert_string, second, end);
                    inserted = true;
                } else {
                    let mut r_line_names_iter_rev = r_line_names_iter.clone().rev();

                    if let Some(r_name_punct) = r_line_names_iter_rev.next() {
                        let insert_string = rm_punct(&i_name_punct);
                        let (first, second) =
                            new_r_line.split_at(new_r_line.find(r_name_punct).unwrap());
                        let second = rm_punct(&second.to_string());
                        let mut end = "},";

                        if new_r_line.ends_with(";") {
                            end = "};";
                        }
                        new_r_line =
                            format!("{}{}{}, {}{}", first, "{", insert_string, second, end);
                        inserted = true;
                    }
                }
            }
        }
        // Advance the iterators
        if let Some(r_name_punct) = r_line_names_iter.next() {
            if let Some(i_name_punct) = i_line_names_iter.next() {
                let r_name = rm_punct(&r_name_punct);

                if i_name > r_name {
                    // If there are no more elements, insert at the end.
                    if let None = r_line_names_iter.peek() {
                        let mut insert_string = i_name_punct.to_string();

                        while let Some(i_name_punct) = i_line_names_iter.next() {
                            insert_string.push_str(i_name_punct);
                        }
                        insert_string = rm_punct(&insert_string).trim_end().to_string();
                        if r_name_punct.ends_with("},") || r_name_punct.ends_with("};") {
                            let (first, second) =
                                new_r_line.split_at(new_r_line.rfind("}").unwrap());

                            new_r_line = format!("{}, {}{}", first, insert_string, second);
                        } else {
                            let (first, second) =
                                r_line.split_at(r_line.find(r_name_punct.as_str()).unwrap());
                            let second = second.trim_end().replace(";", ",");
                            let mut end = "},";

                            if new_r_line.ends_with(";") {
                                end = "};";
                            }
                            new_r_line =
                                format!("{}{}{} {}{}", first, "{", second, insert_string, end);
                        }
                        let mut result_lines: Vec<String> =
                            curr_result.lines().map(|line| line.to_string()).collect();

                        for (i, line) in curr_result.lines().enumerate() {
                            if line == r_line {
                                result_lines.remove(i);
                                result_lines.insert(i, new_r_line);
                                break;
                            }
                        }

                        return Some(result_lines.join("\n"));
                    }
                }
            }
        }
    }
    if inserted {
        let mut result_lines: Vec<String> =
            curr_result.lines().map(|line| line.to_string()).collect();

        for (i, line) in curr_result.lines().enumerate() {
            if line == r_line {
                result_lines.remove(i);
                result_lines.insert(i, new_r_line);
                break;
            }
        }

        return Some(result_lines.join("\n"));
    }

    None
}

/// Inserts the import before the current line.
///
/// For example, "use libafl::executor::InProcessExecutor;" and
/// "use libafl::{
///     feedback::TimeoutFeedback,
///  };", will return:
/// "use libafl::{
///     executor::InProcessExecutor,
///     feedback::TimeoutFeedback,
///  };"
fn insert_before_line(
    i_line: &str,
    r_line: &str,
    r_name_punct: String,
    curr_result: &String,
) -> Option<String> {
    let new_result: String;

    if r_line.ends_with(";") {
        // Change format to multiple import and insert as the first line.
        let (first, second) = r_line.split_at(r_line.find("::").unwrap() + 2);
        let insert_line = format_insert_line(i_line);
        let mut first = first.to_string();
        let second = format_insert_line(second);

        first.push_str("{\n");
        new_result = format!("{}{}{}{}", first, insert_line, second, "};");
    } else {
        // Simply insert the line here..
        let mut result_lines: Vec<String> =
            curr_result.lines().map(|line| line.to_string()).collect();

        for (i, line) in curr_result.lines().enumerate() {
            if line.contains(&r_name_punct) {
                let insert_line = format_insert_line(i_line).replace("\n", "");

                result_lines.insert(i, insert_line);
                break;
            }
        }
        new_result = result_lines.join("\n");
    }

    return Some(new_result);
}

/// Inserts the import before the current line.
///
/// For example, "use libafl::state::StdState;" and
/// "use libafl::{
///     feedback::TimeoutFeedback,
///  };", will return:
/// "use libafl::{
///     feedback::TimeoutFeedback,
///     state::StdState,
///  };"
fn insert_after_line<'a, T>(
    i_line: &str,
    r_line: &str,
    mut r_lines: std::iter::Peekable<T>,
    curr_result: &String,
) -> Option<String>
where
    T: Iterator<Item = &'a str>,
{
    if r_line.ends_with(";") {
        // Change format to multiple import and insert as the last line.
        let new_result: String;
        let (first, second) = r_line.split_at(r_line.find("::").unwrap() + 2);
        let insert_line = format_insert_line(i_line);
        let mut first = first.to_string();
        let second = format_insert_line(second);

        first.push_str("{\n");
        new_result = format!("{}{}{}{}", first, second, insert_line, "};");

        return Some(new_result);
    } else {
        if let Some(end) = r_lines.peek() {
            if end == &"};" {
                // If there are no more elements, insert as the last line.
                let new_result: String;
                let mut result_lines: Vec<String> =
                    curr_result.lines().map(|line| line.to_string()).collect();
                let insert_line = format_insert_line(i_line).replace("\n", "");

                result_lines.insert(result_lines.len() - 1, insert_line);
                new_result = result_lines.join("\n");

                return Some(new_result);
            }
        }
    }

    None
}

/// Formats the import line for insertion.
fn format_insert_line(line: &str) -> String {
    let mut insert_line = line.trim().to_string();

    if insert_line.starts_with("use ") {
        let (_, second) = insert_line.split_once("::").unwrap();
        insert_line = second.to_string();
    }
    insert_line.insert_str(0, &" ".repeat(4));
    insert_line.push('\n');
    insert_line = insert_line.replace(";", ",");

    insert_line
}
