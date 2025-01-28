use std::{
    fs::{create_dir_all, File},
    io::{Error, Write},
    path::PathBuf,
};

use clap::Parser;
use libafl_targets::drcov::DrCovReader;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
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

    #[arg(short, long, help = "Print the metadata of the drcov file.")]
    pub metadata: bool,

    #[arg(short, long, help = "Dump the addresses.")]
    pub addrs: bool,

    #[arg(short, long, help = "Sort the addresses from smallest to biggest.")]
    pub sort: bool,
}

fn main() -> Result<(), Error> {
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

        let mut blocks = drcov.basic_block_addresses_u64();

        if opts.sort {
            blocks.sort_unstable();
        }

        let mut writer: Box<dyn Write> = if let Some(out_dir) = &opts.out_dir {
            // Write files to a directory
            let out_file = out_dir.join(
                input
                    .file_name()
                    .expect("File without filename shouldn't exist"),
            );

            let Ok(file) = File::create_new(&out_file).map_err(|err| {
                eprintln!("Could not create file {out_file:?} - continuing: {err:?}");
            }) else {
                continue;
            };

            println!("Dumping traces from drcov file {input:?} to {out_file:?}",);

            Box::new(file)
        } else {
            Box::new(std::io::stdout())
        };

        // dump to stdout
        let modules = &drcov.module_entries;

        if opts.metadata {
            writeln!(writer, "# {} Modules:", modules.len())?;
            for module in &drcov.module_entries {
                writeln!(
                    writer,
                    "\t{} - [{:#020x}-{:#020x}] {}",
                    module.id,
                    module.base,
                    module.end,
                    module.path.display()
                )?;
            }
            writeln!(writer, "# {} Blocks covered in {input:?}.", blocks.len())?;

            if opts.addrs {
                writeln!(writer)?;
            }
        }

        if opts.addrs {
            for line in blocks {
                writeln!(writer, "{line:#x}")?;
            }
        }
    }

    Ok(())
}
