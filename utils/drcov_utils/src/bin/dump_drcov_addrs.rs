use std::path::PathBuf;

use clap::Parser;
use libafl_targets::drcov::DrCovReader;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[allow(clippy::module_name_repetitions)]
#[command(
    name = "dump_drcov_addrs",
    about,
    long_about = "Writes a list of all addresses from a DrCovFile"
)]
pub struct Opt {
    #[arg(short, long, help = "DrCovFile to read")]
    pub input: PathBuf,
}

fn main() {
    let opts = Opt::parse();
    let drcov = DrCovReader::read(&opts.input).unwrap();
    for line in drcov.basic_block_addresses_u64() {
        println!("0x{line:#x}");
    }
}
