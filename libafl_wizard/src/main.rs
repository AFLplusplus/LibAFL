use libafl_wizard::{
    arrange_code, flowchart_image, separate_code, validate_input, write_code, Question,
};

slint::slint! {
    import { MainWindow } from "./src/ui.slint";
}

fn main() {
    // The question diagram is a vector containing all the questions.
    let mut questions = Question::new();

    // Generate a flowchat image to help guide the user.
    flowchart_image(&questions);

    // Each element is a String, which contains the Rust code associated to a question. This will be used to write to the file.
    let mut code_content: Vec<String> = Vec::new();

    // Marks the questions that produced code that will be written. This has the same index as the questions in their vector.
    // Undo option.
    let mut prod_code: Vec<bool> = vec![false; questions.len()];

    // Index of the current question.
    let mut curr_q = 0;

    let handle = MainWindow::new().unwrap();

    let handle_weak = handle.as_weak();

    let question_copy = questions[curr_q].clone();

    // Initial display.
    handle.set_question(SlintData {
        title: question_copy.title.into(),
        content: question_copy.content.into(),
        answers: slint::ModelRc::from(std::rc::Rc::new(slint::VecModel::from(
            question_copy
                .answers
                .into_iter()
                .map(|s| s.into())
                .collect::<Vec<slint::SharedString>>(),
        ))),
        next: slint::ModelRc::from(std::rc::Rc::new(slint::VecModel::from(
            question_copy
                .next
                .into_iter()
                .map(|s| s.into())
                .collect::<Vec<slint::SharedString>>(),
        ))),
        previous: question_copy.previous.into(),
    });

    // This only gets executed when a button is pressed (answer is chosen).
    handle.on_user_answer(move |answer| {
        // User answer
        let input: String = answer.parse::<String>().unwrap().trim().to_string();
        // Index of the next question and the chosen answer.
        let (next_q, ans_i) = questions[curr_q].resolve_answer(&questions, &input);

        if validate_input(&input, &String::from("Undo")) {
            // If the user chooses to undo a question that produced code, the associated code is removed.
            // Since the Undo option goes backwards, we can simply pop the last piece of code.
            if prod_code[next_q] {
                code_content.pop();
                prod_code[next_q] = false;
            }

            // Also, if we are undoing this question and it skipped others, we undo this too.
            if !questions[next_q].skip.is_empty() {
                questions[next_q]
                    .clone()
                    .check_skip(&mut questions, ans_i, true);
            }
        } else {
            // Adds the code associated to the user choice.
            if questions[curr_q].has_code() {
                questions[curr_q].add_code(&mut code_content, ans_i);
                prod_code[curr_q] = true;
            }

            // If there are any questions that should be skipped because of that answer.
            if !questions[curr_q].skip.is_empty() {
                questions[curr_q]
                    .clone()
                    .check_skip(&mut questions, ans_i, false);
            }

            // Only updates the 'previous' field when going forward (not undoing) in the questions diagram.
            let q_id = questions[curr_q].id.clone();
            questions[next_q].update_previous(q_id);
        }

        curr_q = next_q;

        let question_copy = questions[curr_q].clone();

        handle_weak.unwrap().set_question(SlintData {
            title: question_copy.title.into(),
            content: question_copy.content.into(),
            answers: slint::ModelRc::from(std::rc::Rc::new(slint::VecModel::from(
                question_copy
                    .answers
                    .into_iter()
                    .map(|s| s.into())
                    .collect::<Vec<slint::SharedString>>(),
            ))),
            next: slint::ModelRc::from(std::rc::Rc::new(slint::VecModel::from(
                question_copy
                    .next
                    .into_iter()
                    .map(|s| s.into())
                    .collect::<Vec<slint::SharedString>>(),
            ))),
            previous: question_copy.previous.into(),
        });

        if questions[curr_q].end() {
            // Separate by instances of components, arrange them in the correct order and write to the file.
            let file_name = write_code(arrange_code(separate_code(code_content.clone())));

            println!(
                "File {} successfully created at the ./fuzzers directory.\n\nAll questions answered, you can close the window now!",
                file_name
            );
        }
    });

    // GUI event loop.
    handle.run().unwrap();
}
