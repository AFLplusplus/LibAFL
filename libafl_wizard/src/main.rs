use libafl_wizard::{read_sections, replace_code, validate_input, write_code, Question};
#[cfg(feature = "ui")]
use std::thread;
use std::{io, io::Write};

#[cfg(feature = "ui")]
slint::slint! {
    import { MainWindow } from "./src/ui.slint";
}

#[cfg(not(feature = "ui"))]
fn main() {
    // The question diagram is a vector containing all the questions
    let mut questions = Question::new();

    // Each element is a String, which contains the Rust code associated to a question. This will be used to write to the file
    let mut code_content: Vec<String> = Vec::new();

    // Marks the questions that produced code that will be written. This has the same index as the questions in their vector
    // Undo option
    let mut prod_code: Vec<bool> = vec![false; questions.len()];

    // Index of the current question
    let mut curr_q = 0;
    // Index of the next question
    let mut next_q = 0;
    // Index of the chosen answer
    let mut ans_i = 0;

    let mut valid_ans;

    // User input
    let mut input = String::new();

    // Loads the vectors which contains the ids of questions that may be skipped
    let (in_process_qs, forkserver_qs) = read_sections();

    // Basically, a question is asked, answered by the user and then the generator moves on to the next question.
    while !questions[curr_q].end() {
        // If the question has a title, it means it contains information to show to the user and expects some input
        if questions[curr_q].has_title() {
            questions[curr_q].print_question();

            valid_ans = false;

            while !valid_ans {
                input.clear();
                io::stdout().flush().unwrap();
                io::stdin()
                    .read_line(&mut input)
                    .expect("Failed to get input from stdin.");
                input = input.trim().to_string();

                (next_q, valid_ans, ans_i) = questions[curr_q].resolve_answer(&questions, &input);

                println!("Please type a valid answer: ");
            }
        } else {
            (next_q, _, ans_i) = questions[curr_q].resolve_answer(&questions, &input);
        }

        if validate_input(&input, &String::from("Undo")) {
            // If the user chooses to undo a question that produced code, the associated code is removed.
            // Since the Undo option goes backwards, we can simply pop the last piece of code.
            if prod_code[next_q] {
                code_content.pop();
                prod_code[next_q] = false;
            }
        } else {
            // Adds the code associated to the user choice
            if questions[curr_q].has_code() {
                questions[curr_q].add_code(&mut code_content, ans_i);
                prod_code[curr_q] = true;
            }
        }

        // Skip questions that are no longer possible
        questions[curr_q].clone().check_skip(
            &mut questions,
            &input,
            next_q,
            &in_process_qs,
            &forkserver_qs,
        );

        // Only updates the 'previous' field when going forward in the questions diagram
        if !validate_input(&input, &String::from("Undo")) {
            questions[next_q].update_previous(curr_q);
        }

        curr_q = next_q;
    }

    // Here, the vector 'code_content' contains all the code that will be written to the file, but we need to place the components in the correct order
    // let final_code = arrange_code(code_content);

    replace_code(&mut code_content);

    let file_name = write_code(code_content);

    println!("File {} successfully created!", file_name);
    println!("\nAll questions answered.");
}

#[cfg(feature = "ui")]
fn main() {
    let handle = MainWindow::new().unwrap();
    let handle_weak = handle.as_weak();
    let program_thread = thread::spawn(move || {
        // The question diagram is a vector containing all the questions
        let mut questions = Question::new();

        // Each element is a String, which contains the Rust code associated to a question. This will be used to write to the file
        let mut code_content: Vec<String> = Vec::new();

        // Marks the questions that produced code that will be written. This has the same index as the questions in their vector
        // Undo option
        let mut prod_code: Vec<bool> = vec![false; questions.len()];

        // Index of the current question
        let mut curr_q = 0;
        // Index of the next question
        let mut next_q = 0;
        // Index of the chosen answer
        let mut ans_i = 0;

        let mut valid_ans;

        // User input
        let mut input = String::new();

        // Loads the vectors which contains the ids of questions that may be skipped
        let (in_process_qs, forkserver_qs) = read_sections();

        // Basically, a question is asked, answered by the user and then the generator moves on to the next question.
        while !questions[curr_q].end() {
            // If the question has a title, it means it contains information to show to the user and expects some input
            if questions[curr_q].has_title() {
                valid_ans = false;

                while !valid_ans {
                    input.clear();
                    io::stdout().flush().unwrap();

                    let handle_copy = handle_weak.clone();

                    let question_copy = questions[curr_q].clone();

                    slint::invoke_from_event_loop(move || {
                        handle_copy.unwrap().set_question(SlintData {
                            title: question_copy.title.clone().into(),
                            content: question_copy.content.clone().into(),
                            answers: std::rc::Rc::new(slint::VecModel::from(vec![
                                "answer1".into(),
                                "answer2".into(),
                                "answer3".into(),
                            ]))
                            .into(),
                        })
                    });
                    while input.is_empty() {
                        println!("input = {}", input);
                    }

                    input = input.trim().to_string();

                    (next_q, valid_ans, ans_i) =
                        questions[curr_q].resolve_answer(&questions, &input);
                }
            } else {
                (next_q, _, ans_i) = questions[curr_q].resolve_answer(&questions, &input);
            }

            if validate_input(&input, &String::from("Undo")) {
                // If the user chooses to undo a question that produced code, the associated code is removed.
                // Since the Undo option goes backwards, we can simply pop the last piece of code.
                if prod_code[next_q] {
                    code_content.pop();
                    prod_code[next_q] = false;
                }
            } else {
                // Adds the code associated to the user choice
                if questions[curr_q].has_code() {
                    questions[curr_q].add_code(&mut code_content, ans_i);
                    prod_code[curr_q] = true;
                }
            }

            // Skip questions that are no longer possible
            questions[curr_q].clone().check_skip(
                &mut questions,
                &input,
                next_q,
                &in_process_qs,
                &forkserver_qs,
            );

            // Only updates the 'previous' field when going forward in the questions diagram
            if !validate_input(&input, &String::from("Undo")) {
                questions[next_q].update_previous(curr_q);
            }

            curr_q = next_q;
        }

        // Here, the vector 'code_content' contains all the code that will be written to the file, but we need to place the components in the correct order
        // let final_code = arrange_code(code_content);

        replace_code(&mut code_content);

        let file_name = write_code(code_content);

        println!("File {} successfully created!", file_name);
        println!("\nAll questions answered.");
    });

    // Start the GUI event loop
    handle.run().unwrap();

    program_thread.join().unwrap();
}
