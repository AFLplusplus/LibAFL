use clap::{App, IntoApp, Parser};
use fuzzer_options::FuzzerOptions;

fn custom_func(_: &str) {}

/// subcommand help
#[derive(Parser, Debug)]
#[clap(name = "custom")]
struct CustomFooParser {
    /// a very cromulent option
    #[clap(short, long)]
    bar: String,
}

fn main() {
    // example command line invocation:
    // ./path-to-bin custom --bar stuff
    let cmd: App = CustomFooParser::into_app();

    // with_subcommand takes an `App`, and returns an `App`
    let parser = FuzzerOptions::with_subcommand(cmd);

    // use the `App` to parse everything
    let matches = parser.get_matches();

    // process the results
    if let Some(("custom", sub_matches)) = matches.subcommand() {
        custom_func(sub_matches.value_of("bar").unwrap())
    }

    println!("{:?}", matches);
}
