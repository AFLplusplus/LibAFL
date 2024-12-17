pub mod level;
mod version;

use std::iter;

use clap::Parser;

use crate::args::{level::Level, version::Version};

pub trait ParentArgs {
    fn port(&self) -> u16;
    fn timeout(&self) -> u64;
}

impl ParentArgs for Args {
    fn port(&self) -> u16 {
        self.port
    }
    fn timeout(&self) -> u64 {
        self.timeout
    }
}

pub trait ChildArgs {
    fn argv(&self) -> Vec<String>;
}

impl ChildArgs for Args {
    fn argv(&self) -> Vec<String> {
        iter::once(&self.program)
            .chain(self.args.iter())
            .cloned()
            .collect::<Vec<String>>()
    }
}

pub trait LogArgs {
    fn log_file(&self) -> String;
    fn log_level(&self) -> Level;
}

impl LogArgs for Args {
    fn log_file(&self) -> String {
        self.log_file.clone()
    }
    fn log_level(&self) -> Level {
        self.log_level
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[command(
    version = Version::default(),
    about = "gdb-qemu",
    long_about = "Tool launching qemu-user for debugging"
)]
#[readonly::make]
pub struct Args {
    #[arg(short, long, help = "Port", value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,

    #[arg(short, long, help = "Timeout Ms", default_value_t = 2000)]
    timeout: u64,

    #[arg(
        short,
        long,
        help = "Log file (Requires --log-level)",
        default_value = "gdb_qemu.log",
        requires = "log_level"
    )]
    log_file: String,

    #[arg(short='L', long, help = "Log level", value_enum, default_value_t = Level::Off)]
    log_level: Level,

    #[arg(help = "Name of the qemu-user binary to launch")]
    program: String,

    #[arg(last = true, value_parser, value_delimiter = ' ', num_args = 1.., help = "Arguments passed to the target")]
    args: Vec<String>,
}
