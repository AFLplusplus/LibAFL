use std::{
    fs::{create_dir_all, File},
    io::Write,
    path::PathBuf,
};

use clap::Parser;
use libafl_targets::drcov::DrCovReader;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[allow(clippy::module_name_repetitions)]
#[command(
    name = "drcov_dump_addrs",
    about,
    long_about = "Writes a list of all addresses from a DrCovFile"
)]
pub struct Opt {
    #[arg(short, long, help = "DrCov traces to read", required = true)]
    pub inputs: Vec<PathBuf>,
    #[arg(
        short,
        long,
        help = "Output folder to write address files to. If none is set, this will output all addresses to stdout."
    )]
    pub out_dir: Option<PathBuf>,
}

fn main() {
    let opts = Opt::parse();

    if let Some(out_dir) = &opts.out_dir {
        if !out_dir.exists() {
            if let Err(err) = create_dir_all(out_dir) {
                eprint!("Failed to create dir {out_dir:?}: {err:?}");
            }
        }

        assert!(out_dir.is_dir(), "Out_dir {out_dir:?} not a directory!");
    }

    for input in opts.inputs {
        let Ok(drcov) = DrCovReader::read(&input)
            .map_err(|err| eprint!("Ignored coverage file {input:?}, reason: {err:?}"))
        else {
            continue;
        };

        if let Some(out_dir) = &opts.out_dir {
            // Write files to a directory
            let out_file = out_dir.join(
                input
                    .file_name()
                    .expect("File without filename shouldn't exist"),
            );

            let Ok(mut file) = File::create_new(&out_file).map_err(|err| {
                eprintln!("Could not create file {out_file:?} - continuing: {err:?}");
            }) else {
                continue;
            };

            println!("Dumping addresses from drcov file {input:?} to {out_file:?}");

            for line in drcov.basic_block_addresses_u64() {
                file.write_all(format!("{line:#x}\n").as_bytes())
                    .expect("Could not write to file");
            }
        } else {
            // dump to stdout
            println!("# Blocks covered in {input:?}:");

            for line in drcov.basic_block_addresses_u64() {
                println!("{line:#x}");
            }

            println!();
        }
    }
}
