use libafl_ftg::{
    read_sections, replace_code, skip_questions, validate_answer, write_code, Question,
};
use std::{error::Error, io, process};

fn run() -> Result<(), Box<dyn Error>> {
    // The question diagram is a vector containing all the questions.
    let mut questions = Question::new()?;

    // Each element is a String, which contains the Rust code associated to a question. This will be used to write to the file.
    // Note that these are not in the same position as the questions, they are simply in the order that will be written to the file.
    let mut code_content: Vec<String> = Vec::new();

    // Marks the questions that produced code that will be written. This has the same index as the questions in their vector.
    // Undo option
    let mut prod_code: Vec<bool> = vec![false; questions.len()];

    // Index of the current question
    let mut curr_q = 0;
    // Index of the next question
    let mut next_q;
    // Index of the chosen answer
    let mut ans_i;

    let mut valid_ans;

    // User input
    let mut input = String::new();

    // Loads the vectors which contains the ids of questions that may be skipped.
    let (info_qs, in_process_qs, forkserver_qs) = read_sections()?;

    // This option allows the user to skip informative question.
    // These are questions that don't influence the generation of code, they simply explain the concepts and components used in Libafl.
    print!("{esc}c", esc = 27 as char);
    println!("Do you wish to skip informative questions? [Y/n]");

    loop {
        io::stdin().read_line(&mut input)?;
        input = input.trim().to_string();

        if validate_answer(&input, &String::from("Yes")) {
            skip_questions(&mut questions, &info_qs);
            break;
        } else if validate_answer(&input, &String::from("No")) {
            break;
        }

        println!("Please type a valid answer: ");
    }

    // Basically, a question is asked, answered by the user and then the generator moves on to the next question, until the last one is asked.
    // Note that not all the questions are going to be asked, for example, if the user chose not to use a monitor, the generator shouldn't
    // ask if he wants a monitor with a UI style or a Simple monitor.
    while !questions[curr_q].end() {
        // If the question has a title, it means it contains information to show to the user and expects some input.
        if questions[curr_q].has_title() {
            questions[curr_q].print_question();

            loop {
                input = "".to_string();
                io::stdin().read_line(&mut input)?;
                input = input.trim().to_string();

                (next_q, valid_ans, ans_i) = questions[curr_q].resolve_answer(&questions, &input);

                if valid_ans {
                    break;
                }

                println!("Please type a valid answer: ");
            }
        } else {
            (next_q, _, ans_i) = questions[curr_q].resolve_answer(&questions, &input);
        }

        // Code generation
        if validate_answer(&input, &String::from("Undo")) {
            // If the user chooses to undo a question that produced code, the code is removed.
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

        // Only updates the 'previous' field when going forward in the questions diagram.
        if !validate_answer(&input, &String::from("Undo")) {
            questions[next_q].update_previous(curr_q);
        }

        curr_q = next_q;
    }

    replace_code(&mut code_content);

    write_code(code_content)?;

    print!("{esc}c", esc = 27 as char);
    println!("\nAll questions answered!!!\n\nShutting down...");

    Ok(())
}

fn main() {
    if let Err(err) = run() {
        println!("{}", err);
        process::exit(1);
    }
}
