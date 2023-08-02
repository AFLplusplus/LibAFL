use std::{error::Error, fs::OpenOptions, io, process};

use libafl_ftg::Question;

fn run() -> Result<(), Box<dyn Error>> {
    // Mutable because we have to update the index of the 'previous' field.
    let mut q_diagram = Question::new()?;

    // Basically, a question is asked, answered by the user and then the generator moves on to the next question, until the last one is asked.
    // Note that not all the questions are going to be asked. So if the user chooses not to use a monitor, the generator shouldn't ask
    // if he wants a monitor with a UI style or a Simple monitor.
    let mut q_index = 0;
    let mut input = String::new();

    // Output file, containing the generated fuzzer.
    let mut out_file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open("fuzzer.rs")?;

    while q_index < q_diagram.len() {
        q_diagram[q_index].print_question();

        io::stdin().read_line(&mut input)?;

        while !q_diagram[q_index].validate_answer(&mut input) {
            println!("Please type a valid answer:");
            input = "".to_string();
            io::stdin().read_line(&mut input)?;
        }

        // Code generation

        if q_index < q_diagram.len() - 1 {
            q_index = q_diagram[q_index]
                .clone()
                .next_question(&mut q_diagram, &input, q_index);
        } else {
            q_index += 1;
        }

        input = "".to_string();
    }

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
