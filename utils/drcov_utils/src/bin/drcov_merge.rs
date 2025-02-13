use std::path::PathBuf;

use clap::Parser;
use libafl_targets::drcov::DrCovReader;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[command(
    name = "drcov_merge",
    about,
    long_about = "Merges multiple DrCov coverage files into one"
)]
pub struct Opt {
    #[arg(short, long, help = "DrCovFiles to merge", num_args = 2.., value_delimiter = ' ', required = true)]
    pub inputs: Vec<PathBuf>,
    #[arg(short, long, help = "Output DrCov file")]
    pub output: PathBuf,
    #[arg(
        short,
        long,
        help = "If set, the merged file will contain every block exactly once."
    )]
    pub unique: bool,
}

fn main() {
    env_logger::init();
    let opts = Opt::parse();

    assert!(
        opts.inputs.len() > 1,
        "Need at least two inputs to merge anything."
    );

    let mut inputs = opts.inputs.iter();

    let initial_input = inputs.next().unwrap();

    if opts.unique {
        println!("Unique block mode");
    }

    println!("Reading inital drcov file from {initial_input:?}");
    let mut main_drcov = DrCovReader::read(initial_input).expect("Failed to read fist input!");

    for input in inputs {
        if let Ok(current_drcov) = DrCovReader::read(input)
            .map_err(|err| eprintln!("Warning: failed to read drcov file at {input:?}: {err:?}"))
        {
            println!("Merging {input:?}");
            if let Err(err) = main_drcov.merge(&current_drcov, opts.unique) {
                eprintln!("Warning: failed to merge drcov file at {input:?}: {err:?}");
            }
        }
    }

    main_drcov
        .write(opts.output)
        .expect("Failed to write merged drcov file to output path");
}
