use clap::{App, IntoApp, Parser};
use fuzzer_options::FuzzerOptions;

fn custom_func(_: &str) {}

#[derive(Parser, Debug)]
#[clap(name = "custom")]
/// subcommand help
struct CustomFooParser {
    #[clap(short, long)]
    bar: String,
}

fn main() {
    // example command line invocation:
    // ./path-to-bin custom --bar stuff
    let cmd: App = CustomFooParser::into_app();
    let parser = FuzzerOptions::with_subcommand(cmd);
    let matches = parser.get_matches();

    if let Some(("custom", sub_matches)) = matches.subcommand() {
        custom_func(sub_matches.value_of("bar").unwrap())
    }

    println!("{:?}", matches);
}
