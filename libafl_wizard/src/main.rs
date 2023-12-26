use std::{io, io::Write};

mod answer;
mod question;
mod utils;

use question::{find_question, flowchart_image, Question};
use utils::{
    arrange_code, arrange_imports, clear_terminal_screen, separate_code, separate_imports,
    validate_input, write_code,
};

fn main() {
    // The question diagram is a vector containing all the questions.
    let mut questions = Question::new();
    // Each element is a String, which contains the Rust code associated to a question. This will be used to write to the file.
    let mut code_content: Vec<String> = Vec::new();
    // Index of the current question.
    let mut curr_q = 0;
    // Index of the next question. Note that, when undoing, the next question is the previous one (that led to the current one).
    let mut next_q;
    // Index of the chosen answer.
    let mut ans_i;
    let mut input = String::new();

    // Generate a flowchat image to help guide the user.
    flowchart_image(&questions);

    // Basically, a question is shown, answered by the use and so on, until the last question.
    while questions[curr_q].id != "END" {
        clear_terminal_screen();
        questions[curr_q].print_question();
        print!("\n >> ");
        io::stdout().flush().unwrap();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to get input from stdin.");
        input = input.trim().to_string();

        while !questions[curr_q].is_answer(&input) {
            print!("Please, type a valid answer: ");
            io::stdout().flush().unwrap();
            input.clear();
            io::stdin()
                .read_line(&mut input)
                .expect("Failed to get input from stdin.");
            input = input.trim().to_string();
        }

        if validate_input(&input, &String::from("Undo")) {
            // The "Undo" option makes the generator go back to the previous answered question, so if the user do something by
            // mistake they can correct it.
            next_q = find_question(&questions, &questions[curr_q].previous);

            // If the user chooses to undo a question that produced code, the associated code is removed.
            // Since the Undo option goes backwards, we can simply pop the last piece of code.
            for ans in questions[next_q].answers.iter() {
                if ans.was_chosen && !ans.code.is_empty() {
                    code_content.pop();
                }
            }

            // Also, if we are undoing this question and it skipped others, we undo this too.
            ans_i = questions[curr_q].chosen_answer();
            if !questions[next_q].answers[ans_i].skip.is_empty() {
                questions[next_q]
                    .clone()
                    .unskip_questions(&mut questions, ans_i);
            }

            questions[curr_q].answers[ans_i].was_chosen = false;
        } else {
            (next_q, ans_i) = questions[curr_q].resolve_answer(&questions, &input);
            questions[curr_q].answers[ans_i].was_chosen = true;

            // Adds the code associated to the user choice.
            if questions[curr_q].answers[ans_i].has_code() {
                questions[curr_q].answers[ans_i].add_code(&mut code_content);
            }

            // If there are any questions that should be skipped because of that answer.
            if !questions[curr_q].answers[ans_i].skip.is_empty() {
                questions[curr_q]
                    .clone()
                    .skip_questions(&mut questions, ans_i);
            }

            // Only updates the 'previous' field when going forward (not undoing) in the questions diagram.
            let q_id = questions[curr_q].id.clone();
            questions[next_q].update_previous(q_id);
        }
        input.clear();
        curr_q = next_q;
    }

    let (imports_content, code_content) = separate_imports(code_content);

    // Separate by instances of components, arrange them in the correct order and write to the file.
    let file_name = write_code(
        arrange_code(separate_code(code_content)),
        arrange_imports(imports_content),
    );

    println!(
        "\nFile {} successfully created in the ./fuzzers directory.\nAll questions answered!",
        file_name
    );
}
