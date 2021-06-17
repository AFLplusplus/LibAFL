use std::{
    ffi::OsString,
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    process::{exit, Command},
};

use concolic::{Message, MessageFileReader, MessageFileWriter};
use structopt::StructOpt;

use libafl::bolts::shmem::{ShMem, ShMemProvider, StdShMemProvider};

#[derive(Debug, StructOpt)]
#[structopt(
    name = "dump_constraints",
    about = "Dump tool for concolic constraints."
)]
struct Opt {
    /// Outputs plain text instead of binary
    #[structopt(short, long)]
    plain_text: bool,

    /// Trace file path, "trace" by default.
    #[structopt(parse(from_os_str), short, long)]
    output: Option<PathBuf>,

    /// Target program and arguments
    #[structopt(last = true)]
    program: Vec<OsString>,
}

fn main() {
    let opt = Opt::from_args();

    let mut shmemprovider = StdShMemProvider::default();
    let shmem = shmemprovider
        .new_map(1024 * 1024 * 1024)
        .expect("unable to create shared mapping");
    shmem
        .write_to_env("SHARED_MEMORY_MESSAGES")
        .expect("unable to write shared mapping info to environment");
    let res = Command::new(&opt.program.first().expect("no program argument given"))
        .args(opt.program.iter().skip(1))
        .status()
        .expect("failed to spawn program");

    {// open a new scope to ensure our ressources get dropped before the exit call at the end
        let output_file_path = opt.output.unwrap_or("trace".into());
        let mut output_file =
            BufWriter::new(File::create(output_file_path).expect("unable to open output file"));
        let mut reader = MessageFileReader::new_from_buffer(shmem.map());
        if opt.plain_text {
            while let Some(message) = reader.next_message() {
                if let Ok((id, message)) = message {
                    writeln!(&mut output_file, "{}\t{:?}", id, message)
                        .expect("failed to write to output file");
                } else {
                    break;
                }
            }
        } else {
            let mut writer = MessageFileWriter::new_from_writer(output_file);
            while let Some(message) = reader.next_message() {
                if let Ok((_, message)) = message {
                    writer.write_message(message);
                } else {
                    break;
                }
            }
            writer.write_message(Message::End);
        }
    }

    exit(res.code().expect("failed to get exit code from program"));
}
